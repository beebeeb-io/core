use std::fmt;

use beebeeb_core::kdf::MasterKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{SecretError, SecretStore};

const API_URL: &str = "session.api_url";
const TOKEN_PREFIX: &str = "session.token.";
const APP_IDS: &str = "session.app_ids";
const MASTER_KEY: &str = "session.master_key";
const OWNER: &str = "session.owner";
const GENERATION: &str = "account.generation";
const HARDWARE_ID: &str = "device.hardware_id";
const HARDWARE_IDENTITY_SECRET: &str = "device.hardware_identity_secret";
const ACCOUNT_CHANGE: &str = "session.account_change";

/// The screen-lock check record (`beebeeb_core::screen_lock`, 102 bytes).
pub(crate) const LOCK_SCREEN_CHECK: &str = "lock.screen_check";
/// The failed-try count and the time of the last failure.
pub(crate) const LOCK_ATTEMPTS: &str = "lock.attempts";
/// The "ask for my password when the app starts" setting.
pub(crate) const LOCK_ASK_AT_START: &str = "lock.ask_password_at_start";
/// The mark of a closed vault: it survives a quit and a reboot.
pub(crate) const LOCK_VAULT_CLOSED: &str = "lock.vault_closed";
/// The lock entries belong to the account on the device: they are removed with the device
/// session, at both places core removes one, and kept by an app-only sign-out.
const LOCK_ENTRIES: [&str; 4] = [LOCK_SCREEN_CHECK, LOCK_ATTEMPTS, LOCK_ASK_AT_START, LOCK_VAULT_CLOSED];

const FLAG_ON: &[u8] = b"1";
const FLAG_OFF: &[u8] = b"0";

/// A stored lock flag. `None` means it could not be read (a store failure, or bytes that are
/// neither flag value): the caller treats the vault as closed. An absent entry is `false`.
pub(crate) fn read_lock_flag(store: &dyn SecretStore, name: &str) -> Option<bool> {
    match store.get(name) {
        Ok(None) => Some(false),
        Ok(Some(value)) if value.as_slice() == FLAG_ON => Some(true),
        Ok(Some(value)) if value.as_slice() == FLAG_OFF => Some(false),
        Ok(Some(_)) | Err(_) => None,
    }
}

pub(crate) fn write_lock_flag(store: &dyn SecretStore, name: &str, on: bool) -> Result<(), SecretError> {
    store.set(name, if on { FLAG_ON } else { FLAG_OFF })
}

pub(crate) struct HardwareIdentity {
    id: String,
    secret: Option<Zeroizing<String>>,
}

impl HardwareIdentity {
    pub(crate) fn load_or_create(store: &dyn SecretStore) -> Result<Self, SecretError> {
        let id = match store.get(HARDWARE_ID)? {
            Some(value) => {
                let value = stored_string(&value)?;
                uuid::Uuid::parse_str(&value).map_err(|_| SecretError::Corrupt)?;
                value
            }
            None => {
                let value = uuid::Uuid::new_v4().to_string();
                store.set(HARDWARE_ID, value.as_bytes())?;
                value
            }
        };
        let secret = store
            .get(HARDWARE_IDENTITY_SECRET)?
            .map(|value| stored_string(&value).map(Zeroizing::new))
            .transpose()?;
        Ok(Self { id, secret })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn secret(&self) -> Option<&str> {
        self.secret.as_ref().map(|value| value.as_str())
    }

    pub(crate) fn store_secret(store: &dyn SecretStore, secret: &str) -> Result<(), SecretError> {
        if secret.is_empty() {
            return Err(SecretError::Corrupt);
        }
        store.set(HARDWARE_IDENTITY_SECRET, secret.as_bytes())
    }
}

impl fmt::Debug for HardwareIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HardwareIdentity")
            .field("id", &self.id)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    api_url: String,
    token: String,
    owner: String,
    master_key: MasterKey,
    generation: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("api_url", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .field("owner", &"[REDACTED]")
            .field("master_key", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

impl Session {
    pub fn stored_owner(store: &dyn SecretStore) -> Result<Option<String>, SecretError> {
        store.get(OWNER)?.map(|value| stored_string(&value)).transpose()
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn from_authenticated(
        api_url: &str,
        token: String,
        owner: String,
        master_key: MasterKey,
        generation: u64,
    ) -> Result<Self, SecretError> {
        validate_api_url(api_url)?;
        if token.is_empty() || owner.is_empty() {
            return Err(SecretError::Corrupt);
        }
        Ok(Self {
            api_url: api_url.into(),
            token,
            owner,
            master_key,
            generation,
        })
    }

    pub(crate) fn refresh(&self, token: String, generation: u64) -> Result<Self, SecretError> {
        let key = Zeroizing::new(*self.master_key.to_bytes());
        Self::from_authenticated(
            &self.api_url,
            token,
            self.owner.clone(),
            MasterKey::from_bytes(*key),
            generation,
        )
    }

    pub(crate) fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub(crate) fn open_name(
        &self,
        item_id: &str,
        name_encrypted: &str,
    ) -> Result<beebeeb_core::encrypt::NameMetadata, beebeeb_core::CoreError> {
        beebeeb_core::encrypt::decrypt_name_metadata(&self.master_key, item_id, name_encrypted)
    }

    pub(crate) fn seal_new_folder(
        &self,
        name: &str,
    ) -> Result<(beebeeb_core::item_id::NewItemId, String), beebeeb_core::CoreError> {
        let item = beebeeb_core::item_id::NewItemId::owner(&self.master_key)?;
        let sealed = beebeeb_core::encrypt::encrypt_name_for_new_item(
            &self.master_key,
            &item,
            name,
            None,
            beebeeb_core::chunk_stream::ExpectedChunkFormat::Unrecorded,
        )?;
        Ok((item, sealed))
    }

    pub(crate) fn seal_rename(
        &self,
        item_id: &str,
        current_name_encrypted: &str,
        new_name: &str,
    ) -> Result<String, beebeeb_core::CoreError> {
        let metadata = self.open_name(item_id, current_name_encrypted)?;
        beebeeb_core::rename::encrypt_name_for_request_rename_with_version(
            &self.master_key,
            item_id,
            metadata.chunk_format,
            metadata.version,
            new_name,
            metadata.mime_type.as_deref(),
        )
    }

    #[cfg(feature = "settings")]
    pub(crate) fn seal_settings(
        &self,
        device_id: &uuid::Uuid,
        product: &str,
        plaintext: &str,
    ) -> Result<String, beebeeb_core::CoreError> {
        beebeeb_core::client_meta::ClientMetaKey::new(&self.master_key).seal_settings(device_id, product, plaintext)
    }

    #[cfg(feature = "settings")]
    pub(crate) fn open_settings(
        &self,
        device_id: &uuid::Uuid,
        product: &str,
        envelope: &str,
    ) -> Result<String, beebeeb_core::CoreError> {
        beebeeb_core::client_meta::ClientMetaKey::new(&self.master_key).open_settings(device_id, product, envelope)
    }

    #[cfg(feature = "contacts")]
    pub(crate) fn seal_contact_key(
        &self,
        contact_id: &uuid::Uuid,
        plaintext: &str,
    ) -> Result<String, beebeeb_core::CoreError> {
        beebeeb_core::client_meta::seal_client_meta(
            &self.master_key,
            contact_id,
            Some(contact_id),
            beebeeb_core::client_meta::ClientMetaField::ContactKey,
            plaintext,
        )
    }

    /// A device's hostname as it sealed it under this account's key
    /// (client-meta field 1, keyed by the device id).
    #[cfg(feature = "sync")]
    pub(crate) fn open_device_hostname(
        &self,
        device_id: &uuid::Uuid,
        envelope: &str,
    ) -> Result<String, beebeeb_core::CoreError> {
        beebeeb_core::client_meta::open_client_meta(
            &self.master_key,
            device_id,
            None,
            beebeeb_core::client_meta::ClientMetaField::DeviceHostname,
            envelope,
        )
    }

    #[cfg(feature = "contacts")]
    pub(crate) fn open_contact_key(
        &self,
        contact_id: &uuid::Uuid,
        envelope: &str,
    ) -> Result<String, beebeeb_core::CoreError> {
        beebeeb_core::client_meta::open_client_meta(
            &self.master_key,
            contact_id,
            Some(contact_id),
            beebeeb_core::client_meta::ClientMetaField::ContactKey,
            envelope,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        api_url: &str,
        token: &str,
        owner: &str,
        master_key: [u8; 32],
        generation: u64,
    ) -> Result<Self, SecretError> {
        validate_api_url(api_url)?;
        Ok(Self {
            api_url: api_url.into(),
            token: token.into(),
            owner: owner.into(),
            master_key: MasterKey::from_bytes(master_key),
            generation,
        })
    }

    pub fn save(&self, store: &dyn SecretStore, app_id: &str) -> Result<(), SecretError> {
        validate_api_url(&self.api_url)?;
        if self.owner.is_empty() || self.token.is_empty() || !valid_app_id(app_id) {
            return Err(SecretError::Corrupt);
        }
        let key = Zeroizing::new(self.master_key.to_bytes());
        let generation = self.generation.to_string();
        let previous_owner = store.get(OWNER)?.map(|value| stored_string(&value)).transpose()?;
        let mut app_ids = stored_app_ids(store)?;

        let stored_key = store.get(MASTER_KEY)?;
        if stored_key.as_ref().is_some_and(|stored| stored.len() != 32) {
            return Err(SecretError::Corrupt);
        }
        let account_change_started = store.get(ACCOUNT_CHANGE)?.is_some();
        let first_save = previous_owner.is_none() && !account_change_started;
        if first_save {
            store.set(ACCOUNT_CHANGE, self.owner.as_bytes())?;
        }
        let account_change = match previous_owner.as_deref() {
            Some(owner) => owner != self.owner,
            None => account_change_started,
        };
        if previous_owner.is_none()
            && !account_change_started
            && stored_key
                .as_ref()
                .is_some_and(|stored| stored.as_slice() != key.as_slice())
        {
            return Err(SecretError::OwnerMismatch);
        }
        if account_change {
            store.set(ACCOUNT_CHANGE, self.owner.as_bytes())?;
            store.delete(OWNER)?;
            delete_app_tokens(store, &app_ids, None)?;
            app_ids.clear();
            store.delete(APP_IDS)?;
            for name in [API_URL, MASTER_KEY, HARDWARE_IDENTITY_SECRET]
                .into_iter()
                .chain(LOCK_ENTRIES)
            {
                store.delete(name)?;
            }
        } else if previous_owner.as_deref() == Some(self.owner.as_str())
            && stored_key
                .as_ref()
                .is_some_and(|stored| stored.as_slice() != key.as_slice())
        {
            return Err(SecretError::Corrupt);
        }
        let token_name = token_name(app_id)?;
        if !app_ids.iter().any(|value| value == app_id) {
            app_ids.push(app_id.to_owned());
            app_ids.sort_unstable();
        }
        let encoded_app_ids = serde_json::to_vec(&app_ids).map_err(|_| SecretError::Corrupt)?;
        let values: [(&str, &[u8]); 4] = [
            (API_URL, self.api_url.as_bytes()),
            (MASTER_KEY, key.as_slice()),
            (GENERATION, generation.as_bytes()),
            (APP_IDS, &encoded_app_ids),
        ];
        for (name, value) in values {
            set_if_changed(store, name, value)?;
        }
        set_if_changed(store, &token_name, self.token.as_bytes())?;
        set_if_changed(store, OWNER, self.owner.as_bytes())?;
        if first_save || account_change || account_change_started {
            store.delete(ACCOUNT_CHANGE)?;
        }
        Ok(())
    }

    pub(crate) fn save_replacing(&self, store: &dyn SecretStore, app_id: &str) -> Result<(), SecretError> {
        store.set(ACCOUNT_CHANGE, self.owner.as_bytes())?;
        self.save(store, app_id)
    }

    /// Loads a key only after its separate owner record matches the expected
    /// account. A mismatch leaves the stored account untouched.
    ///
    /// This is a restore path, so it obeys the vault lock: while the closed mark is set, or
    /// cannot be read, it answers `SecretError::VaultClosed` without reading the key entry.
    /// Only core's strong unlock (`Client::unlock_known_device`) loads the key of a closed
    /// vault, and it clears the mark. (`Client::start_from_store` sets the mark when it starts
    /// closed because of the start setting, so that setting holds for this path too.)
    ///
    /// A host that uses the two-level lock does not call this at start: it starts with
    /// `Client::start_from_store` and nothing else. This path follows the closed mark, not the
    /// "ask for my password at start" setting, so on a device whose vault was opened by a
    /// strong unlock it would load the key at a start the setting says must stay closed.
    pub fn load_for_user(
        store: &dyn SecretStore,
        expected_user: &str,
        app_id: &str,
    ) -> Result<Option<Self>, SecretError> {
        if read_lock_flag(store, LOCK_VAULT_CLOSED) != Some(false) {
            return Err(SecretError::VaultClosed);
        }
        Self::load_for_user_proven(store, expected_user, app_id)
    }

    /// The stored token of this app with its owner, without reading the key entry: for
    /// ending that session at the server from a closed vault.
    pub(crate) fn stored_token_for_app(
        store: &dyn SecretStore,
        app_id: &str,
    ) -> Result<Option<(Zeroizing<String>, String)>, SecretError> {
        let Some(owner) = Self::stored_owner_for_app(store, app_id)? else {
            return Ok(None);
        };
        let Some(token) = store.get(&token_name(app_id)?)? else {
            return Ok(None);
        };
        Ok(Some((Zeroizing::new(stored_string(&token)?), owner)))
    }

    /// The owner of the stored session this app is registered in, without reading the key
    /// entry. `None`: no stored session, or none for this app.
    pub(crate) fn stored_owner_for_app(store: &dyn SecretStore, app_id: &str) -> Result<Option<String>, SecretError> {
        if !valid_app_id(app_id) {
            return Err(SecretError::Corrupt);
        }
        let Some(owner) = Self::stored_owner(store)? else {
            return Ok(None);
        };
        Ok(stored_app_ids(store)?
            .iter()
            .any(|value| value == app_id)
            .then_some(owner))
    }

    /// [`Self::load_for_user`] without the vault-lock check: for core's own paths that hold a
    /// proof stronger than the lock (the strong unlock, a change made in an open app, a start
    /// the lock rule allowed).
    pub(crate) fn load_for_user_proven(
        store: &dyn SecretStore,
        expected_user: &str,
        app_id: &str,
    ) -> Result<Option<Self>, SecretError> {
        if expected_user.is_empty() || !valid_app_id(app_id) {
            return Err(SecretError::Corrupt);
        }
        let Some(owner_bytes) = store.get(OWNER)? else {
            if store.get(ACCOUNT_CHANGE)?.is_some() {
                purge_device_session(store, Some(app_id))?;
            }
            return Ok(None);
        };
        let owner = stored_string(&owner_bytes)?;
        if owner != expected_user {
            return Err(SecretError::OwnerMismatch);
        }
        let app_ids = stored_app_ids(store)?;
        let token_name = token_name(app_id)?;
        if !app_ids.iter().any(|value| value == app_id) {
            store.delete(&token_name)?;
            return Ok(None);
        }
        let token = required(store, &token_name)?;
        let api_url = required(store, API_URL)?;
        let master_key = required(store, MASTER_KEY)?;
        if master_key.len() != 32 {
            return Err(SecretError::Corrupt);
        }
        let generation = store
            .get(GENERATION)?
            .map(|bytes| stored_string(&bytes)?.parse().map_err(|_| SecretError::Corrupt))
            .transpose()?
            .unwrap_or(0);
        let api_url = stored_string(&api_url)?;
        validate_api_url(&api_url)?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&master_key);
        Ok(Some(Self {
            api_url,
            token: stored_string(&token)?,
            owner,
            master_key: MasterKey::from_bytes(*key),
            generation,
        }))
    }

    pub fn sign_out_app(store: &dyn SecretStore, app_id: &str) -> Result<(), SecretError> {
        let token_name = token_name(app_id)?;
        store.delete(&token_name)?;
        let mut app_ids = stored_app_ids(store)?;
        app_ids.retain(|value| value != app_id);
        if app_ids.is_empty() {
            store.delete(APP_IDS)
        } else {
            let encoded = serde_json::to_vec(&app_ids).map_err(|_| SecretError::Corrupt)?;
            store.set(APP_IDS, &encoded)
        }
    }

    pub fn sign_out_device(store: &dyn SecretStore) -> Result<u64, SecretError> {
        let current = store
            .get(GENERATION)?
            .map(|bytes| stored_string(&bytes)?.parse::<u64>().map_err(|_| SecretError::Corrupt))
            .transpose()?
            .unwrap_or(0);
        let next = current.checked_add(1).ok_or(SecretError::Corrupt)?;
        store.set(GENERATION, next.to_string().as_bytes())?;
        purge_device_session(store, None)?;
        Ok(next)
    }
}

fn required(store: &dyn SecretStore, name: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    store.get(name)?.ok_or(SecretError::Corrupt)
}

fn set_if_changed(store: &dyn SecretStore, name: &str, value: &[u8]) -> Result<(), SecretError> {
    if store
        .get(name)?
        .as_ref()
        .is_some_and(|stored| stored.as_slice() == value)
    {
        Ok(())
    } else {
        store.set(name, value)
    }
}

fn stored_string(bytes: &[u8]) -> Result<String, SecretError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| SecretError::Corrupt)
}

fn stored_app_ids(store: &dyn SecretStore) -> Result<Vec<String>, SecretError> {
    let Some(value) = store.get(APP_IDS)? else {
        return Ok(Vec::new());
    };
    let app_ids: Vec<String> = serde_json::from_slice(&value).map_err(|_| SecretError::Corrupt)?;
    if app_ids.iter().any(|value| !valid_app_id(value)) {
        return Err(SecretError::Corrupt);
    }
    Ok(app_ids)
}

fn delete_app_tokens(
    store: &dyn SecretStore,
    app_ids: &[String],
    extra_app_id: Option<&str>,
) -> Result<(), SecretError> {
    let mut failed = false;
    for app_id in app_ids.iter().map(String::as_str).chain(extra_app_id) {
        let name = token_name(app_id)?;
        failed |= store.delete(&name).is_err();
    }
    if failed { Err(SecretError::Backend) } else { Ok(()) }
}

fn purge_device_session(store: &dyn SecretStore, extra_app_id: Option<&str>) -> Result<(), SecretError> {
    let (app_ids, registry_error) = match stored_app_ids(store) {
        Ok(app_ids) => (app_ids, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let mut failed = registry_error.is_some() || store.delete(OWNER).is_err();
    failed |= delete_app_tokens(store, &app_ids, extra_app_id).is_err();
    let session_entries = [API_URL, MASTER_KEY, APP_IDS, HARDWARE_IDENTITY_SECRET, ACCOUNT_CHANGE];
    for name in session_entries.into_iter().chain(LOCK_ENTRIES) {
        failed |= store.delete(name).is_err();
    }
    if failed {
        Err(registry_error.unwrap_or(SecretError::Backend))
    } else {
        Ok(())
    }
}

fn token_name(app_id: &str) -> Result<String, SecretError> {
    if !valid_app_id(app_id) {
        return Err(SecretError::Corrupt);
    }
    Ok(format!("{TOKEN_PREFIX}{app_id}"))
}

pub(crate) fn valid_app_id(app_id: &str) -> bool {
    !app_id.is_empty()
        && app_id.len() <= 128
        && app_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_api_url(value: &str) -> Result<(), SecretError> {
    crate::transport::validate_api_base(value)
        .map(|_| ())
        .map_err(|_| SecretError::Corrupt)
}
