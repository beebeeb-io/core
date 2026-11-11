use super::{FlowError, KeyHandle, KeySource, KeySourceKind, UnlockError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision {
    ImmediateWithAlerts,
    WaitWithAlertsAndCancellation,
}

#[derive(Debug, Clone)]
pub struct RecoveryFlow {
    password_available: bool,
    recovery_key: bool,
    wait_completed: bool,
}

impl RecoveryFlow {
    pub fn new(password_available: bool) -> Self {
        Self {
            password_available,
            recovery_key: false,
            wait_completed: false,
        }
    }
    pub fn recovery_key_accepted(mut self) -> Result<Self, FlowError> {
        if self.recovery_key {
            return Err(FlowError::StepNotRequired);
        }
        self.recovery_key = true;
        Ok(self)
    }
    pub fn decision(&self) -> RecoveryDecision {
        if self.password_available {
            RecoveryDecision::ImmediateWithAlerts
        } else {
            RecoveryDecision::WaitWithAlertsAndCancellation
        }
    }
    pub fn wait_completed(&mut self) -> Result<(), FlowError> {
        if self.password_available {
            return Err(FlowError::StepNotRequired);
        }
        if !self.recovery_key {
            return Err(FlowError::StepOutOfOrder);
        }
        self.wait_completed = true;
        Ok(())
    }
    pub fn unlock<H: KeyHandle, S: KeySource<H>>(self, source: &S) -> Result<H, UnlockError<S::Error>> {
        if !self.recovery_key {
            return Err(UnlockError::Flow(FlowError::NotReady));
        }
        if !self.password_available && !self.wait_completed {
            return Err(UnlockError::Flow(FlowError::NotReady));
        }
        if source.kind() != KeySourceKind::RecoveryKey {
            return Err(UnlockError::WrongKeySource);
        }
        source.open().map_err(UnlockError::Source)
    }
}
