/// Marker implemented by an opaque key handle owned by a binding or client.
/// Implementations must not expose raw key bytes.
pub trait KeyHandle {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySourceKind {
    ExistingDevice,
    Approval,
    Passkey,
    RecoveryKey,
}

/// A narrow seam that converts one verified key source into an opaque handle.
pub trait KeySource<H: KeyHandle> {
    type Error;
    fn kind(&self) -> KeySourceKind;
    fn open(&self) -> Result<H, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInPath {
    KnownDevice,
    NewDeviceApproval {
        authenticator_required: bool,
    },
    NewDevicePasskey,
    NewDeviceRecovery {
        authenticator_required: bool,
        transition_phrase: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    StepNotRequired,
    StepOutOfOrder,
    NotReady,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnlockError<E> {
    Flow(FlowError),
    WrongKeySource,
    Source(E),
}

#[derive(Debug, Clone)]
pub struct SignInFlow {
    path: SignInPath,
    password: bool,
    email: bool,
    authenticator: bool,
    approval: bool,
    passkey: bool,
    recovery: bool,
}

impl SignInFlow {
    pub fn new(path: SignInPath) -> Self {
        Self {
            path,
            password: false,
            email: false,
            authenticator: false,
            approval: false,
            passkey: false,
            recovery: false,
        }
    }

    pub fn password_accepted(&mut self) -> Result<(), FlowError> {
        if self.password {
            return Err(FlowError::StepNotRequired);
        }
        self.password = true;
        Ok(())
    }

    pub fn email_code_accepted(&mut self) -> Result<(), FlowError> {
        if !matches!(
            self.path,
            SignInPath::NewDevicePasskey | SignInPath::NewDeviceRecovery { .. }
        ) {
            return Err(FlowError::StepNotRequired);
        }
        if !self.password {
            return Err(FlowError::StepOutOfOrder);
        }
        self.email = true;
        Ok(())
    }

    pub fn authenticator_accepted(&mut self) -> Result<(), FlowError> {
        let required = matches!(
            self.path,
            SignInPath::NewDeviceApproval {
                authenticator_required: true
            } | SignInPath::NewDeviceRecovery {
                authenticator_required: true,
                ..
            }
        );
        if !required {
            return Err(FlowError::StepNotRequired);
        }
        if !self.password {
            return Err(FlowError::StepOutOfOrder);
        }
        self.authenticator = true;
        Ok(())
    }

    pub fn device_approved(&mut self) -> Result<(), FlowError> {
        if !matches!(self.path, SignInPath::NewDeviceApproval { .. }) {
            return Err(FlowError::StepNotRequired);
        }
        if !self.password {
            return Err(FlowError::StepOutOfOrder);
        }
        self.approval = true;
        Ok(())
    }

    pub fn passkey_accepted(&mut self) -> Result<(), FlowError> {
        if !matches!(self.path, SignInPath::NewDevicePasskey) {
            return Err(FlowError::StepNotRequired);
        }
        if !(self.password && self.email) {
            return Err(FlowError::StepOutOfOrder);
        }
        self.passkey = true;
        Ok(())
    }

    pub fn recovery_phrase_entered(&mut self) -> Result<(), FlowError> {
        if !matches!(self.path, SignInPath::NewDeviceRecovery { .. }) {
            return Err(FlowError::StepNotRequired);
        }
        if !(self.password && self.email) {
            return Err(FlowError::StepOutOfOrder);
        }
        self.recovery = true;
        Ok(())
    }

    pub fn ready_key_source(&self) -> Option<KeySourceKind> {
        match self.path {
            SignInPath::KnownDevice if self.password => Some(KeySourceKind::ExistingDevice),
            SignInPath::NewDeviceApproval { authenticator_required }
                if self.password && self.approval && (!authenticator_required || self.authenticator) =>
            {
                Some(KeySourceKind::Approval)
            }
            SignInPath::NewDevicePasskey if self.password && self.email && self.passkey => Some(KeySourceKind::Passkey),
            SignInPath::NewDeviceRecovery {
                authenticator_required, ..
            } if self.password && self.email && self.recovery && (!authenticator_required || self.authenticator) => {
                Some(KeySourceKind::RecoveryKey)
            }
            _ => None,
        }
    }

    pub fn unlock<H: KeyHandle, S: KeySource<H>>(self, source: &S) -> Result<H, UnlockError<S::Error>> {
        let required = self.ready_key_source().ok_or(UnlockError::Flow(FlowError::NotReady))?;
        if source.kind() != required {
            return Err(UnlockError::WrongKeySource);
        }
        source.open().map_err(UnlockError::Source)
    }
}

#[derive(Debug, Clone)]
pub struct NewDeviceFlow {
    inner: SignInFlow,
    screen_sharing_warning: bool,
}

impl NewDeviceFlow {
    pub fn approval(authenticator_required: bool) -> Self {
        Self {
            inner: SignInFlow::new(SignInPath::NewDeviceApproval { authenticator_required }),
            screen_sharing_warning: false,
        }
    }
    pub fn passkey() -> Self {
        Self {
            inner: SignInFlow::new(SignInPath::NewDevicePasskey),
            screen_sharing_warning: false,
        }
    }
    pub fn recovery(authenticator_required: bool) -> Self {
        Self {
            inner: SignInFlow::new(SignInPath::NewDeviceRecovery {
                authenticator_required,
                transition_phrase: false,
            }),
            screen_sharing_warning: true,
        }
    }
    pub fn existing_account_phrase() -> Self {
        Self {
            inner: SignInFlow::new(SignInPath::NewDeviceRecovery {
                authenticator_required: false,
                transition_phrase: true,
            }),
            screen_sharing_warning: true,
        }
    }
    pub fn screen_sharing_warning_required(&self) -> bool {
        self.screen_sharing_warning
    }
    pub fn password_accepted(&mut self) -> Result<(), FlowError> {
        self.inner.password_accepted()
    }
    pub fn email_code_accepted(&mut self) -> Result<(), FlowError> {
        self.inner.email_code_accepted()
    }
    pub fn authenticator_accepted(&mut self) -> Result<(), FlowError> {
        self.inner.authenticator_accepted()
    }
    pub fn device_approved(&mut self) -> Result<(), FlowError> {
        self.inner.device_approved()
    }
    pub fn passkey_accepted(&mut self) -> Result<(), FlowError> {
        self.inner.passkey_accepted()
    }
    pub fn recovery_phrase_entered(&mut self) -> Result<(), FlowError> {
        self.inner.recovery_phrase_entered()
    }
    pub fn ready_key_source(&self) -> Option<KeySourceKind> {
        self.inner.ready_key_source()
    }
    pub fn unlock<H: KeyHandle, S: KeySource<H>>(self, source: &S) -> Result<H, UnlockError<S::Error>> {
        self.inner.unlock(source)
    }
}
