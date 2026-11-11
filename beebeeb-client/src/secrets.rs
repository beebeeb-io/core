use std::{collections::HashMap, sync::Mutex};

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret storage is unavailable")]
    Backend,
    #[error("stored client state is incomplete or invalid")]
    Corrupt,
    #[error("the stored key belongs to another account")]
    OwnerMismatch,
}

pub trait SecretStore: Send + Sync {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), SecretError>;
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError>;
    fn delete(&self, name: &str) -> Result<(), SecretError>;
}

#[derive(Default)]
pub struct MemorySecretStore {
    values: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    reads: Mutex<HashMap<String, usize>>,
}

impl MemorySecretStore {
    #[cfg(test)]
    pub(crate) fn reset_reads(&self) {
        if let Ok(mut reads) = self.reads.lock() {
            reads.clear();
        }
    }

    #[cfg(test)]
    pub(crate) fn read_count_for(&self, name: &str) -> usize {
        self.reads
            .lock()
            .ok()
            .and_then(|reads| reads.get(name).copied())
            .unwrap_or(0)
    }
}

impl SecretStore for MemorySecretStore {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), SecretError> {
        self.values
            .lock()
            .map_err(|_| SecretError::Backend)?
            .insert(name.to_owned(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        *self
            .reads
            .lock()
            .map_err(|_| SecretError::Backend)?
            .entry(name.to_owned())
            .or_default() += 1;
        Ok(self.values.lock().map_err(|_| SecretError::Backend)?.get(name).cloned())
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        self.values.lock().map_err(|_| SecretError::Backend)?.remove(name);
        Ok(())
    }
}

/// The Keychain exists only on Apple targets. Elsewhere the store keeps no
/// fields and every call returns `SecretError::Backend`; the constructor keeps
/// one signature on every platform so callers need no cfg of their own.
pub struct KeychainSecretStore {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    service: String,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    access_group: String,
}

impl KeychainSecretStore {
    pub fn new(service: impl Into<String>, access_group: impl Into<String>) -> Self {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            Self {
                service: service.into(),
                access_group: access_group.into(),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = (service, access_group);
            Self {}
        }
    }
}

impl SecretStore for KeychainSecretStore {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), SecretError> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            use security_framework::access_control::{ProtectionMode, SecAccessControl};
            use security_framework::passwords::{AccessControlOptions, set_generic_password_options};
            let access = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                AccessControlOptions::empty().bits(),
            )
            .map_err(|_| SecretError::Backend)?;
            let mut options = self.options(name);
            options.set_access_control(access);
            set_generic_password_options(value, options).map_err(|_| SecretError::Backend)
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = (name, value);
            Err(SecretError::Backend)
        }
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            use security_framework::passwords::generic_password;
            use security_framework_sys::base::errSecItemNotFound;
            match generic_password(self.options(name)) {
                Ok(value) => Ok(Some(Zeroizing::new(value))),
                Err(error) if error.code() == errSecItemNotFound => Ok(None),
                Err(_) => Err(SecretError::Backend),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = name;
            Err(SecretError::Backend)
        }
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            use security_framework::passwords::delete_generic_password_options;
            use security_framework_sys::base::errSecItemNotFound;
            match delete_generic_password_options(self.options(name)) {
                Ok(()) => Ok(()),
                Err(error) if error.code() == errSecItemNotFound => Ok(()),
                Err(_) => Err(SecretError::Backend),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = name;
            Err(SecretError::Backend)
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl KeychainSecretStore {
    fn options(&self, name: &str) -> security_framework::passwords::PasswordOptions {
        let mut options = security_framework::passwords::PasswordOptions::new_generic_password(&self.service, name);
        options.set_access_group(&self.access_group);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }
}
