use super::*;

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceSettingsData {
    pub cache_bytes: u64,
    pub thumbnail_bytes: u64,
    pub wifi_only: bool,
    pub upload_staging_bytes: u64,
    pub version_history_enabled: bool,
    pub version_history_days: u16,
}

impl From<DeviceSettingsData> for DeviceSettings {
    fn from(value: DeviceSettingsData) -> Self {
        Self {
            cache_bytes: value.cache_bytes,
            thumbnail_bytes: value.thumbnail_bytes,
            wifi_only: value.wifi_only,
            upload_staging_bytes: value.upload_staging_bytes,
            version_history_enabled: value.version_history_enabled,
            version_history_days: value.version_history_days,
        }
    }
}

impl From<DeviceSettings> for DeviceSettingsData {
    fn from(value: DeviceSettings) -> Self {
        Self {
            cache_bytes: value.cache_bytes,
            thumbnail_bytes: value.thumbnail_bytes,
            wifi_only: value.wifi_only,
            upload_staging_bytes: value.upload_staging_bytes,
            version_history_enabled: value.version_history_enabled,
            version_history_days: value.version_history_days,
        }
    }
}

#[derive(uniffi::Object)]
pub struct SettingsServiceHandle {
    pub(super) root: Arc<NativeClientHandle>,
    pub(super) store: Arc<StoreHandle>,
}

#[uniffi::export]
impl SettingsServiceHandle {
    pub fn save_local(
        &self,
        device_id: String,
        product: String,
        settings: DeviceSettingsData,
    ) -> Result<(), ServiceError> {
        let session = self.root.session()?;
        let mut store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        beebeeb_client::settings::save_local_settings(&mut store, &session, &device_id, &product, &settings.into())
            .map(|_| ())
            .map_err(map_client_error)
    }

    pub fn load_local(&self, device_id: String, product: String) -> Result<Option<DeviceSettingsData>, ServiceError> {
        let session = self.root.session()?;
        let store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        beebeeb_client::settings::load_local_settings(&store, &session, &device_id, &product)
            .map(|value| value.map(Into::into))
            .map_err(map_client_error)
    }

    pub fn set_version_history(&self, enabled: bool, retention_days: u16) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.set_version_history(enabled, retention_days))
            .map_err(map_client_error)
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceData {
    pub id: String,
    pub hostname: String,
    pub platform: String,
    pub version: Option<String>,
    pub last_seen: String,
    pub created_at: String,
}

#[derive(uniffi::Object)]
pub struct DeviceServiceHandle {
    pub(crate) root: Arc<NativeClientHandle>,
}

#[uniffi::export]
impl DeviceServiceHandle {
    pub fn list(&self) -> Result<Vec<DeviceData>, ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.list_devices())
            .map(|result| {
                result
                    .devices
                    .into_iter()
                    .map(|device| DeviceData {
                        id: device.id,
                        hostname: device.hostname,
                        platform: device.platform,
                        version: device.bb_version,
                        last_seen: device.last_seen,
                        created_at: device.created_at,
                    })
                    .collect()
            })
            .map_err(map_client_error)
    }

    pub fn remove(&self, id: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.remove_device(&id))
            .map_err(map_client_error)
    }
}
