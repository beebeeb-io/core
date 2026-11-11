use super::*;

pub struct RecoveryAttempt {
    id: String,
    token: Zeroizing<String>,
    ready_at: Option<beebeeb_api::routes::Timestamp>,
    state: RecoveryState,
}

impl std::fmt::Debug for RecoveryAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryAttempt")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("ready_at", &self.ready_at)
            .field("state", &self.state)
            .finish()
    }
}

impl RecoveryAttempt {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn ready_at(&self) -> Option<&beebeeb_api::routes::Timestamp> {
        self.ready_at.as_ref()
    }

    /// Whether the server still holds this attempt in its wait. The device
    /// clock is not consulted: it can be off by any amount. Refresh with
    /// `recovery_status` to learn when the wait has passed.
    pub fn waits(&self) -> bool {
        self.state == RecoveryState::Pending
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        id: &str,
        token: &str,
        ready_at: Option<beebeeb_api::routes::Timestamp>,
        state: RecoveryState,
    ) -> Self {
        Self {
            id: id.into(),
            token: Zeroizing::new(token.into()),
            ready_at,
            state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Pending,
    Ready,
    Completed,
    Cancelled,
    /// The server's window to complete this attempt has passed; start again.
    Expired,
}

impl RecoveryState {
    fn parse(value: &str) -> Result<Self, AuthError> {
        match value {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            _ => Err(AuthError::MalformedAnswer),
        }
    }
}

/// The server decides readiness on its own clock. `ready_at` is only checked
/// for shape, so a waiting attempt can still show when its wait ends.
fn recovery_state(status: &str, ready_at: &str) -> Result<RecoveryState, AuthError> {
    let state = RecoveryState::parse(status)?;
    if state == RecoveryState::Pending {
        chrono::DateTime::parse_from_rfc3339(ready_at).map_err(|_| AuthError::MalformedAnswer)?;
    }
    Ok(state)
}

pub struct RecoveryCancelToken {
    id: String,
    token: Zeroizing<String>,
}

impl RecoveryCancelToken {
    pub fn from_alert(id: impl Into<String>, token: Zeroizing<String>) -> Result<Self, AuthError> {
        let id = id.into();
        if id.is_empty() || token.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        Ok(Self { id, token })
    }
}

impl std::fmt::Debug for RecoveryCancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCancelToken")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Default)]
pub struct RecoveryChanges {
    pub new_password: Option<Zeroizing<String>>,
    pub new_email: Option<String>,
    pub email_verification_code: Option<Zeroizing<String>>,
    pub new_authenticator: Option<Zeroizing<String>>,
    pub authenticator_code: Option<Zeroizing<String>>,
    pub remove_authenticator: bool,
}

pub struct RecoveredSession {
    session_token: Zeroizing<String>,
    canonical_email: String,
    owner: String,
}

impl RecoveredSession {
    pub fn canonical_email(&self) -> &str {
        &self.canonical_email
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_complete(&self) -> bool {
        !self.session_token.is_empty()
    }
}

impl std::fmt::Debug for RecoveredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredSession")
            .field("session_token", &"[REDACTED]")
            .field("canonical_email", &self.canonical_email)
            .field("owner", &self.owner)
            .finish()
    }
}

impl Client {
    pub async fn start_recovery(
        &self,
        email: &str,
        master_key: &MasterKey,
        password_proof: Option<RecoveryPasswordProof>,
    ) -> Result<RecoveryAttempt, AuthError> {
        let requested_email = canonical_email(email);
        if requested_email.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let challenge = self
            .execute(
                &proposed::recovery_challenge(),
                &proposed::RecoveryChallengeRequest { email: requested_email },
            )
            .await?;
        if challenge.canonical_email.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let password_proven = match password_proof {
            Some(proof) if proof.canonical_email == challenge.canonical_email => Some(proof.token.to_string()),
            Some(_) => return Err(AuthError::AccountOwnership),
            None => None,
        };
        let core_challenge = CoreKeyProofChallenge::from_parts(
            decode_fixed::<32>(&challenge.nonce)?,
            decode_fixed::<32>(&challenge.server_public)?,
        );
        let response = answer_challenge(
            master_key,
            KeyProofBinding::Recovery {
                canonical_email: challenge.canonical_email.as_bytes(),
            },
            &core_challenge,
        )
        .map_err(|_| AuthError::KeyProof)?;
        let status = self
            .execute(
                &proposed::start_recovery(),
                &proposed::RecoveryStart {
                    email: challenge.canonical_email,
                    challenge_id: challenge.challenge_id,
                    response: STANDARD.encode(response.as_bytes()),
                    password_proven,
                },
            )
            .await?;
        let token = status.recovery_token;
        if status.id.is_empty() || token.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let state = recovery_state(&status.status, &status.ready_at)?;
        Ok(RecoveryAttempt {
            id: status.id,
            token: Zeroizing::new(token),
            ready_at: Some(status.ready_at),
            state,
        })
    }

    pub async fn recovery_status(&self, attempt: &mut RecoveryAttempt) -> Result<RecoveryState, AuthError> {
        let status = self
            .execute_bearer(&proposed::recovery_status(&attempt.id), &(), &attempt.token)
            .await?;
        let state = recovery_state(&status.status, &status.ready_at)?;
        attempt.ready_at = Some(status.ready_at);
        attempt.state = state;
        Ok(state)
    }

    pub async fn complete_recovery(
        &self,
        attempt: &RecoveryAttempt,
        email: &str,
        changes: RecoveryChanges,
    ) -> Result<RecoveredSession, AuthError> {
        if changes.new_password.is_none()
            && changes.new_email.is_none()
            && changes.new_authenticator.is_none()
            && !changes.remove_authenticator
        {
            return Err(AuthError::MalformedAnswer);
        }
        match (attempt.state, attempt.ready_at.as_ref()) {
            (RecoveryState::Ready, _) => {}
            (RecoveryState::Pending, Some(ready_at)) => {
                return Err(AuthError::RecoveryWaiting {
                    ready_at: ready_at.clone(),
                });
            }
            _ => return Err(AuthError::RecoveryNotReady),
        }
        let new_email = changes.new_email.map(|value| canonical_email(&value));
        if new_email.is_some() && changes.email_verification_code.is_none() {
            let response = self
                .execute_bearer(
                    &proposed::complete_recovery(&attempt.id),
                    &proposed::RecoveryComplete {
                        opaque_registration: None,
                        new_email,
                        email_verification_code: None,
                        authenticator: None,
                    },
                    &attempt.token,
                )
                .await?;
            if response.status.as_deref() == Some("email_verification_required") {
                return Err(AuthError::RecoveryEmailVerificationRequired);
            }
            return Err(AuthError::MalformedAnswer);
        }

        let opaque_registration = match changes.new_password {
            Some(password) => {
                let registration = client_registration_start(password.as_bytes()).map_err(|_| AuthError::Crypto)?;
                let state = Zeroizing::new(registration.state);
                let started = self
                    .execute_bearer(
                        &proposed::recovery_opaque_register(&attempt.id),
                        &proposed::RecoveryOpaqueRegister {
                            client_message: STANDARD.encode(registration.message),
                        },
                        &attempt.token,
                    )
                    .await?;
                let server_message = STANDARD
                    .decode(started.server_message)
                    .map_err(|_| AuthError::MalformedAnswer)?;
                Some(
                    STANDARD.encode(
                        client_registration_finish(&state, password.as_bytes(), &server_message)
                            .map_err(|_| AuthError::Crypto)?,
                    ),
                )
            }
            None if new_email.is_some() => return Err(AuthError::MalformedAnswer),
            None => None,
        };
        let authenticator = if changes.remove_authenticator {
            if changes.new_authenticator.is_some() || changes.authenticator_code.is_some() {
                return Err(AuthError::MalformedAnswer);
            }
            Some(proposed::AuthenticatorChange {
                action: "remove".into(),
                secret: None,
                code: None,
            })
        } else {
            match (changes.new_authenticator, changes.authenticator_code) {
                (Some(secret), Some(code)) => Some(proposed::AuthenticatorChange {
                    action: "replace".into(),
                    secret: Some(secret),
                    code: Some(code),
                }),
                (None, None) => None,
                _ => return Err(AuthError::MalformedAnswer),
            }
        };
        let response = self
            .execute_bearer(
                &proposed::complete_recovery(&attempt.id),
                &proposed::RecoveryComplete {
                    opaque_registration,
                    new_email,
                    email_verification_code: changes.email_verification_code,
                    authenticator,
                },
                &attempt.token,
            )
            .await?;
        let session_token = response.session_token.ok_or(AuthError::MalformedAnswer)?;
        let owner = response.user_id.ok_or(AuthError::RecoveryAccountIdentityMissing)?;
        if session_token.is_empty() || owner.is_empty() || response.key_state.as_deref() != Some("proven") {
            return Err(AuthError::MalformedAnswer);
        }
        Ok(RecoveredSession {
            session_token: Zeroizing::new(session_token),
            canonical_email: canonical_email(email),
            owner,
        })
    }

    /// Installs a completed recovery as the active session. The recovery
    /// response already represents a proven account key, so no second key
    /// proof round trip is needed.
    pub fn install_recovered_session(
        &self,
        recovered: &RecoveredSession,
        master_key: MasterKey,
        api_url: &str,
        store: &dyn SecretStore,
    ) -> Result<InstalledSession, AuthError> {
        self.install_recovered_session_inner(recovered, master_key, api_url, store, false)
    }

    pub fn install_recovered_session_replacing_account(
        &self,
        recovered: &RecoveredSession,
        master_key: MasterKey,
        api_url: &str,
        store: &dyn SecretStore,
        _replacement: AccountReplacement,
    ) -> Result<InstalledSession, AuthError> {
        self.install_recovered_session_inner(recovered, master_key, api_url, store, true)
    }

    fn install_recovered_session_inner(
        &self,
        recovered: &RecoveredSession,
        master_key: MasterKey,
        api_url: &str,
        store: &dyn SecretStore,
        replace_account: bool,
    ) -> Result<InstalledSession, AuthError> {
        if Session::stored_owner(store)?
            .as_deref()
            .is_some_and(|owner| owner != recovered.owner)
            && !replace_account
        {
            return Err(AuthError::AnotherAccountOnDevice);
        }
        let generation = self.generation().checked_add(1).ok_or(AuthError::MalformedAnswer)?;
        let session = Session::from_authenticated(
            api_url,
            recovered.session_token.to_string(),
            recovered.owner.clone(),
            master_key,
            generation,
        )?;
        if replace_account {
            session.save_replacing(store, self.app_id())?;
        } else {
            session.save(store, self.app_id())?;
        }
        self.set_session(&session)?;
        Ok(InstalledSession {
            owner: recovered.owner.clone(),
            generation,
        })
    }

    pub async fn cancel_recovery(&self, id: &str) -> Result<(), AuthError> {
        self.execute(&proposed::cancel_recovery(id), &())
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn cancel_recovery_with_token(&self, cancellation: RecoveryCancelToken) -> Result<(), AuthError> {
        self.execute(
            &proposed::cancel_recovery_with_token(&cancellation.id),
            &proposed::RecoveryCancel {
                cancel_token: Some(cancellation.token.to_string()),
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }
}
