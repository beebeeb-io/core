use super::*;

#[derive(Debug, Clone, uniffi::Record)]
pub struct ShareData {
    pub id: String,
    pub file_id: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(uniffi::Object)]
pub struct ShareServiceHandle {
    pub(super) root: Arc<NativeClientHandle>,
}

#[uniffi::export]
impl ShareServiceHandle {
    pub fn create_link(
        &self,
        file_id: String,
        wrapped_file_key: String,
        expires_in_hours: Option<i64>,
        passphrase: Option<String>,
    ) -> Result<ShareData, ServiceError> {
        self.root
            .runtime
            .block_on(
                self.root
                    .client
                    .create_share_link(&file_id, &wrapped_file_key, expires_in_hours, passphrase),
            )
            .map(|share| ShareData {
                id: share.id,
                file_id: share.file_id,
                expires_at: share.expires_at,
            })
            .map_err(map_client_error)
    }

    pub fn revoke_folder_link(&self, id: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.revoke_folder_link(&id))
            .map_err(map_client_error)
    }
}

#[derive(uniffi::Object)]
pub struct ContactServiceHandle {
    pub(super) root: Arc<NativeClientHandle>,
    pub(super) store: Arc<StoreHandle>,
}

#[uniffi::export]
impl ContactServiceHandle {
    pub fn observe(&self, contact_id: String, observed_at: i64) -> Result<String, ServiceError> {
        let public_key = self
            .root
            .runtime
            .block_on(self.root.client.fetch_contact_public_key(&contact_id))
            .map_err(map_client_error)?;
        let mut store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        let trust = beebeeb_client::contacts::observe_contact_key(&mut store, &contact_id, &public_key, observed_at)
            .map_err(map_client_error)?;
        Ok(match trust {
            ContactTrust::FirstUse => "first_use",
            ContactTrust::Trusted => "trusted",
            ContactTrust::KeyChanged => "key_changed",
        }
        .into())
    }

    pub fn accept(&self, contact_id: String, observed_at: i64) -> Result<(), ServiceError> {
        let public_key = self
            .root
            .runtime
            .block_on(self.root.client.fetch_contact_public_key(&contact_id))
            .map_err(map_client_error)?;
        let mut store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        beebeeb_client::contacts::accept_contact_key(&mut store, &contact_id, &public_key, observed_at)
            .map_err(map_client_error)
    }
}
