use beebeeb_api::{proposed, routes::settings as api};
use beebeeb_core::system_folders::Service;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{Client, ClientError, Session};

const SETTINGS_KEY: &str = "data-settings-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageLimits {
    pub cache_bytes: u64,
    pub thumbnail_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSettings {
    pub cache_bytes: u64,
    pub thumbnail_bytes: u64,
    pub wifi_only: bool,
    #[serde(default = "default_upload_staging_bytes")]
    pub upload_staging_bytes: u64,
    pub version_history_enabled: bool,
    pub version_history_days: u16,
}

const fn default_upload_staging_bytes() -> u64 {
    512 * 1024 * 1024
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Store(#[from] beebeeb_store::StoreError),
    #[error(transparent)]
    Core(#[from] beebeeb_core::CoreError),
    #[error("the device id is invalid")]
    InvalidDevice,
    #[error("settings data is invalid")]
    InvalidData,
}

pub fn save_local_settings(
    store: &mut beebeeb_store::Store,
    session: &Session,
    device_id: &str,
    product: &str,
    settings: &DeviceSettings,
) -> Result<String, SettingsError> {
    let id = Uuid::parse_str(device_id).map_err(|_| SettingsError::InvalidDevice)?;
    let json = serde_json::to_string(settings).map_err(|_| SettingsError::InvalidData)?;
    let envelope = session.seal_settings(&id, product, &json)?;
    store.put_device_setting(device_id, product, SETTINGS_KEY, envelope.as_bytes())?;
    Ok(envelope)
}

pub fn load_local_settings(
    store: &beebeeb_store::Store,
    session: &Session,
    device_id: &str,
    product: &str,
) -> Result<Option<DeviceSettings>, SettingsError> {
    let id = Uuid::parse_str(device_id).map_err(|_| SettingsError::InvalidDevice)?;
    let Some(bytes) = store.device_setting(device_id, product, SETTINGS_KEY)? else {
        return Ok(None);
    };
    let envelope = std::str::from_utf8(&bytes).map_err(|_| SettingsError::InvalidData)?;
    let json = session.open_settings(&id, product, envelope)?;
    serde_json::from_str(&json)
        .map(Some)
        .map_err(|_| SettingsError::InvalidData)
}

impl Client {
    pub async fn sync_settings(
        &self,
        store: &mut beebeeb_store::Store,
        session: &Session,
        device_id: &str,
        product: &str,
        settings: &DeviceSettings,
    ) -> Result<(), SettingsError> {
        self.person_call(crate::LockedAction::ChangeSettings)?;
        let envelope = save_local_settings(store, session, device_id, product, settings)?;
        self.execute(
            &api::set_preference(&format!("client_meta.settings.{device_id}.{product}")),
            &api::SetPreference {
                value: Value::String(envelope),
            },
        )
        .await?;
        Ok(())
    }

    pub async fn restore_synced_settings(
        &self,
        store: &mut beebeeb_store::Store,
        session: &Session,
        device_id: &str,
        product: &str,
    ) -> Result<Option<DeviceSettings>, SettingsError> {
        self.person_call(crate::LockedAction::ChangeSettings)?;
        let preference: api::Preference = self
            .execute(
                &api::preference(&format!("client_meta.settings.{device_id}.{product}")),
                &(),
            )
            .await?;
        let Some(envelope) = preference.value.as_str() else {
            return Ok(None);
        };
        let id = Uuid::parse_str(device_id).map_err(|_| SettingsError::InvalidDevice)?;
        let json = session.open_settings(&id, product, envelope)?;
        let settings: DeviceSettings = serde_json::from_str(&json).map_err(|_| SettingsError::InvalidData)?;
        save_local_settings(store, session, device_id, product, &settings)?;
        Ok(Some(settings))
    }

    pub async fn set_version_history(&self, enabled: bool, retention_days: u16) -> Result<(), ClientError> {
        self.person_call(crate::LockedAction::ChangeSettings)?;
        self.execute(
            &api::set_version_setting(),
            &api::SetVersionSetting {
                scope: "account".into(),
                target_id: None,
                enabled,
                max_versions: None,
                retention_days: Some(i32::from(retention_days)),
            },
        )
        .await
        .map(|_| ())
    }

    /// Turn a system service on with its folder, always at the top level
    /// (LD-0113: a system folder never has a parent).
    pub async fn enable_system_service(
        &self,
        service: Service,
        folder_id: String,
        name_encrypted: String,
    ) -> Result<proposed::ServiceFolder, ClientError> {
        self.person_call(crate::LockedAction::ChangeSettings)?;
        self.execute(
            &proposed::enable_service(service),
            &proposed::ServiceEnable {
                folder_id,
                name_encrypted,
            },
        )
        .await
    }

    pub async fn disable_system_service(&self, service: Service, move_to_trash: bool) -> Result<(), ClientError> {
        self.person_call(crate::LockedAction::ChangeSettings)?;
        self.execute(
            &proposed::disable_service(service),
            &proposed::ServiceDisable { move_to_trash },
        )
        .await
        .map(|_| ())
    }
}

pub use beebeeb_core::system_folders;
