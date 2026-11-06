pub use beebeeb_core::contact_keys::{PinCheck, check_pin, key_fingerprint, safety_number};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{Client, ClientError, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactTrust {
    FirstUse,
    Trusted,
    KeyChanged,
}

pub fn observe_contact_key(
    store: &mut beebeeb_store::Store,
    contact_id: &str,
    public_key: &[u8],
    observed_at: i64,
) -> Result<ContactTrust, beebeeb_store::StoreError> {
    let remembered = store.contact_key(contact_id)?;
    match remembered {
        None => {
            store.put_contact_key(&beebeeb_store::ContactKey {
                contact_id: contact_id.to_string(),
                public_key: public_key.to_vec(),
                observed_at,
            })?;
            Ok(ContactTrust::FirstUse)
        }
        Some(remembered) if remembered.public_key == public_key => Ok(ContactTrust::Trusted),
        Some(_) => Ok(ContactTrust::KeyChanged),
    }
}

/// Persist a key change only after the app has shown the warning and the
/// person explicitly accepts the new identity.
pub fn accept_contact_key(
    store: &mut beebeeb_store::Store,
    contact_id: &str,
    public_key: &[u8],
    observed_at: i64,
) -> Result<(), beebeeb_store::StoreError> {
    store.put_contact_key(&beebeeb_store::ContactKey {
        contact_id: contact_id.to_string(),
        public_key: public_key.to_vec(),
        observed_at,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncedContactKey {
    public_key: String,
    observed_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ContactServiceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Store(#[from] beebeeb_store::StoreError),
    #[error(transparent)]
    Core(#[from] beebeeb_core::CoreError),
    #[error("the contact or device id is invalid")]
    InvalidId,
    #[error("the synced contact record is invalid")]
    InvalidRecord,
}

impl Client {
    pub async fn fetch_contact_public_key(&self, contact_id: &str) -> Result<Vec<u8>, ContactServiceError> {
        Uuid::parse_str(contact_id).map_err(|_| ContactServiceError::InvalidId)?;
        let answer: beebeeb_api::routes::auth::PublicKey = self
            .execute(&beebeeb_api::routes::auth::public_key(contact_id), &())
            .await?;
        if answer.user_id != contact_id {
            return Err(ContactServiceError::InvalidRecord);
        }
        let key = base64::engine::general_purpose::STANDARD
            .decode(answer.public_key)
            .map_err(|_| ContactServiceError::InvalidRecord)?;
        if key.len() != 32 {
            return Err(ContactServiceError::InvalidRecord);
        }
        Ok(key)
    }

    pub async fn observe_contact_key_from_server(
        &self,
        store: &mut beebeeb_store::Store,
        contact_id: &str,
        observed_at: i64,
    ) -> Result<ContactTrust, ContactServiceError> {
        let public_key = self.fetch_contact_public_key(contact_id).await?;
        observe_contact_key(store, contact_id, &public_key, observed_at).map_err(Into::into)
    }

    pub async fn accept_contact_key_from_server(
        &self,
        store: &mut beebeeb_store::Store,
        contact_id: &str,
        observed_at: i64,
    ) -> Result<(), ContactServiceError> {
        let public_key = self.fetch_contact_public_key(contact_id).await?;
        accept_contact_key(store, contact_id, &public_key, observed_at).map_err(Into::into)
    }

    pub async fn observe_and_sync_contact_key(
        &self,
        store: &mut beebeeb_store::Store,
        session: &Session,
        device_id: &str,
        contact_id: &str,
        public_key: &[u8],
        observed_at: i64,
    ) -> Result<ContactTrust, ContactServiceError> {
        let trust = observe_contact_key(store, contact_id, public_key, observed_at)?;
        if trust == ContactTrust::KeyChanged {
            return Ok(trust);
        }
        let contact = Uuid::parse_str(contact_id).map_err(|_| ContactServiceError::InvalidId)?;
        Uuid::parse_str(device_id).map_err(|_| ContactServiceError::InvalidId)?;
        let plaintext = serde_json::to_string(&SyncedContactKey {
            public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
            observed_at,
        })
        .map_err(|_| ContactServiceError::InvalidRecord)?;
        let envelope = session.seal_contact_key(&contact, &plaintext)?;
        self.execute(
            &beebeeb_api::routes::settings::set_preference(&format!("client_meta.contact.{contact_id}")),
            &beebeeb_api::routes::settings::SetPreference {
                value: Value::String(envelope),
            },
        )
        .await?;
        Ok(trust)
    }

    pub async fn refresh_contact_key(
        &self,
        store: &mut beebeeb_store::Store,
        session: &Session,
        device_id: &str,
        contact_id: &str,
    ) -> Result<Option<ContactTrust>, ContactServiceError> {
        let preference: beebeeb_api::routes::settings::Preference = self
            .execute(
                &beebeeb_api::routes::settings::preference(&format!("client_meta.contact.{contact_id}")),
                &(),
            )
            .await?;
        let Some(envelope) = preference.value.as_str() else {
            return Ok(None);
        };
        let contact = Uuid::parse_str(contact_id).map_err(|_| ContactServiceError::InvalidId)?;
        Uuid::parse_str(device_id).map_err(|_| ContactServiceError::InvalidId)?;
        let plaintext = session.open_contact_key(&contact, envelope)?;
        let record: SyncedContactKey =
            serde_json::from_str(&plaintext).map_err(|_| ContactServiceError::InvalidRecord)?;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(record.public_key)
            .map_err(|_| ContactServiceError::InvalidRecord)?;
        observe_contact_key(store, contact_id, &public_key, record.observed_at)
            .map(Some)
            .map_err(Into::into)
    }
}
