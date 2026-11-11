use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewDeviceUnlockPath {
    Approval,
    Passkey,
    RecoveryKey,
}

pub struct NewDeviceUnlock {
    accepted: PasswordAccepted,
    flow: NewDeviceFlow,
    path: NewDeviceUnlockPath,
    master_key: Option<MasterKey>,
    email_code_ticket: Option<proposed::EmailCodeTicket>,
}

impl std::fmt::Debug for NewDeviceUnlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewDeviceUnlock")
            .field("accepted", &self.accepted)
            .field("path", &self.path)
            .field("master_key", &self.master_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl NewDeviceUnlock {
    pub fn provide_email_code_ticket(&mut self, ticket: proposed::EmailCodeTicket) -> Result<(), AuthError> {
        if !matches!(
            self.path,
            NewDeviceUnlockPath::Passkey | NewDeviceUnlockPath::RecoveryKey
        ) || self.email_code_ticket.is_some()
        {
            return Err(AuthError::InvalidTransition {
                step: "new-device email-code unlock",
                requirement: "email-code ticket is not expected in this state",
            });
        }
        self.flow
            .email_code_accepted()
            .map_err(|_| AuthError::InvalidTransition {
                step: "new-device email-code unlock",
                requirement: "email-code state could not be accepted",
            })?;
        self.email_code_ticket = Some(ticket);
        Ok(())
    }

    pub fn approval(mut accepted: PasswordAccepted) -> Result<Self, AuthError> {
        let authenticator_required = accepted.authenticator_required;
        let mut flow = NewDeviceFlow::approval(authenticator_required);
        flow.password_accepted().map_err(|_| AuthError::InvalidTransition {
            step: "new-device approval",
            requirement: "password state could not be accepted",
        })?;
        if authenticator_required {
            if !accepted.factor_satisfied {
                return Err(AuthError::InvalidTransition {
                    step: "new-device approval",
                    requirement: "authenticator factor was not satisfied",
                });
            }
            flow.authenticator_accepted()
                .map_err(|_| AuthError::InvalidTransition {
                    step: "new-device approval",
                    requirement: "authenticator state could not be accepted",
                })?;
        }
        accepted.factor_satisfied = false;
        Ok(Self {
            accepted,
            flow,
            path: NewDeviceUnlockPath::Approval,
            master_key: None,
            email_code_ticket: None,
        })
    }

    pub fn passkey(accepted: PasswordAccepted) -> Result<Self, AuthError> {
        let mut flow = NewDeviceFlow::passkey();
        flow.password_accepted().map_err(|_| AuthError::InvalidTransition {
            step: "new-device passkey unlock",
            requirement: "password state could not be accepted",
        })?;
        if accepted.email_code_satisfied {
            flow.email_code_accepted().map_err(|_| AuthError::InvalidTransition {
                step: "new-device passkey unlock",
                requirement: "email-code state could not be accepted",
            })?;
        }
        Ok(Self {
            accepted,
            flow,
            path: NewDeviceUnlockPath::Passkey,
            master_key: None,
            email_code_ticket: None,
        })
    }

    pub fn recovery(accepted: PasswordAccepted) -> Result<Self, AuthError> {
        let authenticator_required = accepted.authenticator_required;
        let mut flow = NewDeviceFlow::recovery(authenticator_required);
        flow.password_accepted().map_err(|_| AuthError::InvalidTransition {
            step: "new-device recovery-key unlock",
            requirement: "password state could not be accepted",
        })?;
        if accepted.email_code_satisfied {
            flow.email_code_accepted().map_err(|_| AuthError::InvalidTransition {
                step: "new-device recovery-key unlock",
                requirement: "email-code state could not be accepted",
            })?;
        }
        if authenticator_required {
            if !accepted.factor_satisfied {
                return Err(AuthError::InvalidTransition {
                    step: "new-device recovery-key unlock",
                    requirement: "authenticator factor was not satisfied",
                });
            }
            flow.authenticator_accepted()
                .map_err(|_| AuthError::InvalidTransition {
                    step: "new-device recovery-key unlock",
                    requirement: "authenticator state could not be accepted",
                })?;
        }
        Ok(Self {
            accepted,
            flow,
            path: NewDeviceUnlockPath::RecoveryKey,
            master_key: None,
            email_code_ticket: None,
        })
    }

    pub fn provide_approval(
        &mut self,
        material: beebeeb_core::device_link::AccountKeyMaterial,
    ) -> Result<(), AuthError> {
        if self.path != NewDeviceUnlockPath::Approval || self.master_key.is_some() {
            return Err(AuthError::InvalidTransition {
                step: "new-device approval",
                requirement: "approval material is not expected in this state",
            });
        }
        self.flow.device_approved().map_err(|_| AuthError::InvalidTransition {
            step: "new-device approval",
            requirement: "device approval could not be accepted",
        })?;
        self.master_key = Some(material.into_master_key());
        Ok(())
    }

    pub fn provide_passkey(&mut self, master_key: MasterKey) -> Result<(), AuthError> {
        if self.path != NewDeviceUnlockPath::Passkey || self.master_key.is_some() {
            return Err(AuthError::InvalidTransition {
                step: "new-device passkey unlock",
                requirement: "passkey material is not expected in this state",
            });
        }
        self.flow.passkey_accepted().map_err(|_| AuthError::InvalidTransition {
            step: "new-device passkey unlock",
            requirement: "passkey material could not be accepted",
        })?;
        self.master_key = Some(master_key);
        Ok(())
    }

    pub fn provide_recovery_key(&mut self, master_key: MasterKey) -> Result<(), AuthError> {
        if self.path != NewDeviceUnlockPath::RecoveryKey || self.master_key.is_some() {
            return Err(AuthError::InvalidTransition {
                step: "new-device recovery-key unlock",
                requirement: "recovery key is not expected in this state",
            });
        }
        self.flow
            .recovery_phrase_entered()
            .map_err(|_| AuthError::InvalidTransition {
                step: "new-device recovery-key unlock",
                requirement: "recovery key could not be accepted",
            })?;
        self.master_key = Some(master_key);
        Ok(())
    }

    pub fn into_ready(self) -> Result<ReadyNewDevice, AuthError> {
        if self.flow.ready_key_source().is_none() {
            return Err(AuthError::InvalidTransition {
                step: "new-device installation",
                requirement: "unlock ceremony is incomplete",
            });
        }
        Ok(ReadyNewDevice {
            accepted: self.accepted,
            master_key: self.master_key.ok_or(AuthError::InvalidTransition {
                step: "new-device installation",
                requirement: "account key is missing",
            })?,
            email_code_ticket: self.email_code_ticket,
        })
    }
}

pub struct ReadyNewDevice {
    pub(super) accepted: PasswordAccepted,
    pub(super) master_key: MasterKey,
    pub(super) email_code_ticket: Option<proposed::EmailCodeTicket>,
}

impl std::fmt::Debug for ReadyNewDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadyNewDevice([REDACTED])")
    }
}

impl Client {
    pub async fn submit_unlock_email_code(
        &self,
        unlock: &mut NewDeviceUnlock,
        challenge: String,
        code: String,
    ) -> Result<proposed::EmailCodeTicket, AuthError> {
        let ticket = self.submit_email_code(challenge, code).await?;
        unlock.provide_email_code_ticket(proposed::EmailCodeTicket {
            email_code_ticket: ticket.email_code_ticket.clone(),
            expires_in: ticket.expires_in,
        })?;
        Ok(ticket)
    }
}
