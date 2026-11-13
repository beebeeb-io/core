use super::*;

impl Client {
    pub fn existing_account_phrase_flow() -> NewDeviceFlow {
        NewDeviceFlow::existing_account_phrase()
    }

    pub async fn sign_out_this_app(&self, store: &dyn SecretStore) -> Result<(), AuthError> {
        let network = self.execute_retired_logout().await.map(|_| ());
        let stored = Session::sign_out_app(store, self.app_id());
        let local = self.sign_out_authentication().map(|_| ());
        network?;
        stored?;
        local?;
        Ok(())
    }

    pub async fn unlock_known_device(
        &self,
        mut accepted: PasswordAccepted,
        store: &dyn SecretStore,
    ) -> Result<InstalledSession, AuthError> {
        if Session::stored_owner(store)?.as_deref() != Some(accepted.owner.as_str()) {
            return Err(AuthError::AnotherAccountOnDevice);
        }
        // The strong unlock is the one path that loads the key of a closed vault: the server
        // accepted the password (and the authenticator code when the account has one), and
        // the key is proven for the new session before anything is installed.
        let stored =
            Session::load_for_user_proven(store, &accepted.owner, self.app_id())?.ok_or(AuthError::AccountOwnership)?;
        self.prove_key_for_sign_in(&mut accepted, stored.master_key(), None)
            .await?;
        if let Err(error) = self
            .report_installed_device(accepted.hardware_id.as_deref(), store)
            .await
        {
            let _ = self.clear_authentication();
            return Err(error);
        }
        let generation = self.generation().checked_add(1).ok_or(AuthError::MalformedAnswer)?;
        let refreshed = stored.refresh(accepted.session_token.to_string(), generation)?;
        let record = self.seal_screen_check(&mut accepted).await;
        if let Err(error) = self.save_strong_install(&refreshed, &accepted, store, record, false) {
            let _ = self.clear_authentication();
            return Err(error);
        }
        // The session this one replaces is ended at the server, so a closed-and-opened vault
        // leaves no live session behind.
        if stored.token() != refreshed.token() {
            self.end_session_best_effort(stored.token(), &accepted.owner).await;
        }
        Ok(InstalledSession {
            owner: accepted.owner,
            generation,
        })
    }

    pub async fn install_new_device(
        &self,
        ready: ReadyNewDevice,
        api_url: &str,
        store: &dyn SecretStore,
    ) -> Result<InstalledSession, AuthError> {
        self.install_new_device_inner(ready, api_url, store, false).await
    }

    /// Replaces a different account only after the caller showed and received
    /// explicit confirmation of the last-device key-loss warning.
    pub async fn install_new_device_replacing_account(
        &self,
        ready: ReadyNewDevice,
        api_url: &str,
        store: &dyn SecretStore,
        _replacement: AccountReplacement,
    ) -> Result<InstalledSession, AuthError> {
        self.install_new_device_inner(ready, api_url, store, true).await
    }

    async fn install_new_device_inner(
        &self,
        ready: ReadyNewDevice,
        api_url: &str,
        store: &dyn SecretStore,
        replace_account: bool,
    ) -> Result<InstalledSession, AuthError> {
        let ReadyNewDevice {
            mut accepted,
            master_key,
            email_code_ticket,
        } = ready;
        if Session::stored_owner(store)?
            .as_deref()
            .is_some_and(|owner| owner != accepted.owner)
            && !replace_account
        {
            return Err(AuthError::AnotherAccountOnDevice);
        }
        self.prove_key_for_sign_in(&mut accepted, &master_key, email_code_ticket)
            .await?;
        if let Err(error) = self
            .report_installed_device(accepted.hardware_id.as_deref(), store)
            .await
        {
            let _ = self.clear_authentication();
            return Err(error);
        }
        let generation = self.generation().checked_add(1).ok_or(AuthError::MalformedAnswer)?;
        let session = Session::from_authenticated(
            api_url,
            accepted.session_token.to_string(),
            accepted.owner.clone(),
            master_key,
            generation,
        )?;
        let record = self.seal_screen_check(&mut accepted).await;
        if let Err(error) = self.save_strong_install(&session, &accepted, store, record, replace_account) {
            let _ = self.clear_authentication();
            return Err(error);
        }
        Ok(InstalledSession {
            owner: accepted.owner,
            generation,
        })
    }

    /// Saves an installed session and, in the same step, the lock's part of it: the closed
    /// mark is cleared, the check record of the password that was just proven is stored, and
    /// the app is open. Nothing before this point wrote any of them.
    fn save_strong_install(
        &self,
        session: &Session,
        accepted: &PasswordAccepted,
        store: &dyn SecretStore,
        record: Option<beebeeb_core::screen_lock::ScreenCheckRecord>,
        replace_account: bool,
    ) -> Result<(), AuthError> {
        if replace_account {
            session.save_replacing(store, self.app_id())?;
        } else {
            session.save(store, self.app_id())?;
        }
        persist_hardware_identity(store, accepted)?;
        self.finish_strong_install(store, record)?;
        self.install_session(session)?;
        self.with_lock_flow(beebeeb_api::flows::LockFlow::known_device_unlocked)?
            .map_err(|error| lock::refused("session installation", error))
    }

    async fn report_installed_device(
        &self,
        hardware_id: Option<&str>,
        store: &dyn SecretStore,
    ) -> Result<(), AuthError> {
        let stored_hardware;
        let hardware_id = match hardware_id {
            Some(hardware_id) => hardware_id,
            None => {
                stored_hardware = HardwareIdentity::load_or_create(store)?;
                stored_hardware.id()
            }
        };
        self.execute(
            &devices::register(),
            &devices::Register {
                // The server folds keyless registrations into one entry per
                // platform, so the hardware identity keys this device's entry.
                // Apps on one device share that identity and so one entry.
                client_key: Some(hardware_id.to_owned()),
                hostname_encrypted: None,
                hostname: None,
                platform: self.reported_platform().to_owned(),
                bb_version: Some(self.reported_client_version().to_owned()),
                push_token: None,
                hardware_id: Some(hardware_id.to_owned()),
                reported_name: Some(self.reported_device_name().to_owned()),
            },
        )
        .await
        .map(|_: devices::Device| ())
        .map_err(Into::into)
    }

    async fn prove_key_for_sign_in(
        &self,
        accepted: &mut PasswordAccepted,
        master_key: &MasterKey,
        email_code_ticket: Option<proposed::EmailCodeTicket>,
    ) -> Result<(), AuthError> {
        self.set_authentication(accepted.session_token.to_string(), accepted.owner.clone())?;
        let result = self
            .prove_session_key_with_ticket(
                master_key,
                &accepted.owner,
                email_code_ticket.map(|ticket| ticket.email_code_ticket),
            )
            .await;
        match result {
            Ok(hardware_identity_secret) => {
                accepted.hardware_identity_secret = hardware_identity_secret.map(Zeroizing::new);
                Ok(())
            }
            Err(error) => {
                let _ = self.clear_authentication();
                Err(error)
            }
        }
    }

    pub async fn prove_session_key(&self, master_key: &MasterKey) -> Result<(), AuthError> {
        let owner = self.authenticated_owner()?;
        self.prove_session_key_with_ticket(master_key, &owner, None)
            .await
            .map(|_| ())
    }

    async fn prove_session_key_with_ticket(
        &self,
        master_key: &MasterKey,
        expected_account_id: &str,
        email_code_ticket: Option<String>,
    ) -> Result<Option<String>, AuthError> {
        let challenge = self.execute(&proposed::start_key_proof(), &()).await?;
        let core_challenge = decode_key_proof_challenge(&challenge)?;
        let session_id = uuid::Uuid::parse_str(&challenge.session_id).map_err(|_| AuthError::InvalidAnswer {
            step: "key-proof start",
            field: "session_id",
        })?;
        let account_id = uuid::Uuid::parse_str(&challenge.account_id).map_err(|_| AuthError::InvalidAnswer {
            step: "key-proof start",
            field: "account_id",
        })?;
        if account_id.hyphenated().to_string() != expected_account_id {
            return Err(AuthError::InvalidAnswer {
                step: "key-proof start",
                field: "account_id",
            });
        }
        let response = answer_challenge(
            master_key,
            KeyProofBinding::Session {
                session_id: session_id.as_bytes(),
                account_id: account_id.as_bytes(),
            },
            &core_challenge,
        )
        .map_err(|_| AuthError::KeyProof)?;
        let finish = self
            .execute(
                &proposed::finish_key_proof(),
                &proposed::KeyProofAnswer {
                    response: STANDARD_NO_PAD.encode(response.as_bytes()),
                    email_code_ticket,
                },
            )
            .await?;
        if finish.key_state != "proven" {
            return Err(AuthError::KeyProof);
        }
        Ok(finish.hardware_identity_secret)
    }
}

fn persist_hardware_identity(store: &dyn SecretStore, accepted: &PasswordAccepted) -> Result<(), AuthError> {
    match (&accepted.hardware_id, &accepted.hardware_identity_secret) {
        (Some(_), Some(secret)) => HardwareIdentity::store_secret(store, secret).map_err(Into::into),
        (_, None) => Ok(()),
        (None, Some(_)) => Err(AuthError::InvalidAnswer {
            step: "session installation",
            field: "hardware_identity_secret without hardware_id",
        }),
    }
}
