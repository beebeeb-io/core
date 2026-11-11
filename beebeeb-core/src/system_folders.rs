//! Pure ownership rules for folders managed by a Beebeeb service.

use crate::CoreError;

pub const SYSTEM_FOLDER_MANAGED_CODE: &str = "system_folder_managed";
pub const SYSTEM_FOLDER_MANAGED_MESSAGE: &str =
    "This folder is managed by a Beebeeb service. Turn that service on or off in account settings.";

/// Services allowed to own a system folder. Unknown wire values never become
/// an enum variant and are denied by the maintenance rule below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    MailBackup,
}

impl Service {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MailBackup => "mail_backup",
        }
    }
}

impl TryFrom<&str> for Service {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "mail_backup" => Ok(Self::MailBackup),
            _ => Err(CoreError::InvalidInput("unknown system-folder service".into())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceOperation {
    Repair,
    Cleanup,
}

/// Whether client maintenance may mutate a folder. Unmanaged folders remain
/// available to ordinary repair and cleanup. A managed folder is available
/// only to its owning service; every unknown marker is denied by default.
pub fn client_maintenance_may_touch(
    managed_by: Option<&str>,
    acting_service: Option<Service>,
    _operation: MaintenanceOperation,
) -> bool {
    let Some(marker) = managed_by else {
        return true;
    };
    let Ok(owner) = Service::try_from(marker) else {
        return false;
    };
    acting_service == Some(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_owning_service_may_repair_or_clean_up() {
        for operation in [MaintenanceOperation::Repair, MaintenanceOperation::Cleanup] {
            assert!(client_maintenance_may_touch(None, None, operation));
            assert!(!client_maintenance_may_touch(Some("mail_backup"), None, operation));
            assert!(client_maintenance_may_touch(
                Some("mail_backup"),
                Some(Service::MailBackup),
                operation
            ));
        }
    }

    #[test]
    fn unknown_managers_are_denied() {
        assert!(!client_maintenance_may_touch(
            Some("future_service"),
            Some(Service::MailBackup),
            MaintenanceOperation::Repair,
        ));
    }

    #[test]
    fn stable_error_contract_is_exact() {
        assert_eq!(SYSTEM_FOLDER_MANAGED_CODE, "system_folder_managed");
        assert!(SYSTEM_FOLDER_MANAGED_MESSAGE.contains("account settings"));
    }
}
