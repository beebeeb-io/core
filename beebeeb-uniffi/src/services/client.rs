use super::*;

#[derive(Debug, Clone, uniffi::Record)]
pub struct EngineEventData {
    pub kind: String,
    pub generation: Option<u64>,
    pub file_id: Option<String>,
    pub observed: Option<u64>,
    pub highest: Option<u64>,
    pub sequence_id: Option<i64>,
    pub user_sequence: Option<i64>,
}

impl From<EngineEvent> for EngineEventData {
    fn from(value: EngineEvent) -> Self {
        let mut data = Self {
            kind: String::new(),
            generation: None,
            file_id: None,
            observed: None,
            highest: None,
            sequence_id: None,
            user_sequence: None,
        };
        match value {
            EngineEvent::AccountChanged { generation } => {
                data.kind = "account_changed".into();
                data.generation = Some(generation);
            }
            EngineEvent::AccountMismatch => data.kind = "account_mismatch".into(),
            EngineEvent::SessionExpired => data.kind = "session_expired".into(),
            EngineEvent::HandOff { .. } => data.kind = "hand_off".into(),
            EngineEvent::VersionRollback {
                file_id,
                observed,
                highest,
            } => {
                data.kind = "version_rollback".into();
                data.file_id = Some(file_id);
                data.observed = Some(observed);
                data.highest = Some(highest);
            }
            EngineEvent::SyncCaughtUp { seq_id, user_seq } => {
                data.kind = "sync_caught_up".into();
                data.sequence_id = Some(seq_id);
                data.user_sequence = Some(user_seq);
            }
            EngineEvent::WorkStopped => data.kind = "work_stopped".into(),
        }
        data
    }
}

#[derive(uniffi::Object)]
pub struct EventStreamHandle {
    runtime: ClientRuntime,
    receiver: Mutex<tokio::sync::broadcast::Receiver<EngineEvent>>,
}

#[uniffi::export]
impl EventStreamHandle {
    pub fn next(&self, timeout_ms: u64) -> Result<Option<EngineEventData>, ServiceError> {
        let mut receiver = self.receiver.lock().map_err(|_| ServiceError::unavailable())?;
        let wait = async {
            match tokio::time::timeout(Duration::from_millis(timeout_ms), receiver.recv()).await {
                Ok(Ok(event)) => Ok(Some(event.into())),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => Err(ServiceError::unavailable()),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => Ok(None),
                Err(_) => Ok(None),
            }
        };
        self.runtime.block_on(wait)
    }
}

#[derive(uniffi::Object)]
pub struct NativeClientHandle {
    pub(crate) client: Arc<Client>,
    pub(crate) runtime: ClientRuntime,
    pub(crate) api_base: String,
    pub(crate) app_id: String,
    pub(crate) secret_store: Arc<KeychainSecretStore>,
    pub(crate) secret_access: Option<Box<dyn SecretStoreCallback>>,
    pub(crate) session: Mutex<Option<Arc<Session>>>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NativeClientConfiguration {
    pub api_base: String,
    pub client_name: String,
    pub client_version: String,
    pub app_id: String,
    pub keychain_service: String,
    pub keychain_access_group: String,
    pub runtime_profile: RuntimeProfile,
}

impl NativeClientHandle {
    pub(crate) fn session(&self) -> Result<Arc<Session>, ServiceError> {
        self.session
            .lock()
            .map_err(|_| ServiceError::unavailable())?
            .clone()
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::SessionRequired))
    }

    pub(crate) fn load_installed_session(&self, owner: &str) -> Result<(), ServiceError> {
        let session = Session::load_for_user(self.secret_store.as_ref(), owner, &self.app_id)
            .map_err(|_| ServiceError::new(ServiceErrorKind::Storage))?
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::Storage))?;
        self.client.set_session(&session).map_err(map_client_error)?;
        *self.session.lock().map_err(|_| ServiceError::unavailable())? = Some(Arc::new(session));
        Ok(())
    }
}

#[uniffi::export]
impl NativeClientHandle {
    #[uniffi::constructor]
    pub fn new(
        configuration: NativeClientConfiguration,
        secret_access: Option<Box<dyn SecretStoreCallback>>,
    ) -> Result<Arc<Self>, ServiceError> {
        let app_id = configuration.app_id;
        let api_base = configuration.api_base;
        let config = ClientConfig::new(configuration.client_name, configuration.client_version, app_id.clone());
        let client = Arc::new(Client::with_reqwest(config, &api_base).map_err(map_client_error)?);
        let runtime = match configuration.runtime_profile {
            RuntimeProfile::Application => ClientRuntime::multi_thread(),
            RuntimeProfile::Lightweight => ClientRuntime::lightweight(),
        }
        .map_err(map_client_error)?;
        Ok(Arc::new(Self {
            client,
            runtime,
            api_base,
            app_id,
            secret_store: Arc::new(KeychainSecretStore::new(
                configuration.keychain_service,
                configuration.keychain_access_group,
            )),
            secret_access,
            session: Mutex::new(None),
        }))
    }

    pub fn load_session(&self, expected_user: String, app_id: String) -> Result<bool, ServiceError> {
        if self
            .secret_access
            .as_ref()
            .is_some_and(|callback| !callback.authorize_access("session".into()))
        {
            return Err(ServiceError::new(ServiceErrorKind::Storage));
        }
        let session = Session::load_for_user(self.secret_store.as_ref(), &expected_user, &app_id)
            .map_err(|_| ServiceError::new(ServiceErrorKind::Storage))?;
        let Some(session) = session else {
            return Ok(false);
        };
        self.client.set_session(&session).map_err(map_client_error)?;
        *self.session.lock().map_err(|_| ServiceError::unavailable())? = Some(Arc::new(session));
        Ok(true)
    }

    pub fn generation(&self) -> u64 {
        self.client.generation()
    }

    pub fn events(&self) -> Arc<EventStreamHandle> {
        Arc::new(EventStreamHandle {
            runtime: self.runtime.clone(),
            receiver: Mutex::new(self.client.events().subscribe()),
        })
    }

    pub fn auth(self: &Arc<Self>) -> Arc<AuthServiceHandle> {
        Arc::new(AuthServiceHandle { root: self.clone() })
    }

    pub fn files(self: &Arc<Self>) -> Arc<FileServiceHandle> {
        Arc::new(FileServiceHandle { root: self.clone() })
    }
}

#[derive(uniffi::Object)]
pub struct StoreHandle {
    pub(crate) store: Arc<Mutex<Store>>,
}

#[uniffi::export]
impl StoreHandle {
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, ServiceError> {
        let store = Store::open(path).map_err(|_| ServiceError::new(ServiceErrorKind::Storage))?;
        Ok(Arc::new(Self {
            store: Arc::new(Mutex::new(store)),
        }))
    }

    pub fn prepare_for_suspension(&self) -> Result<(), ServiceError> {
        self.store
            .lock()
            .map_err(|_| ServiceError::new(ServiceErrorKind::Storage))?
            .prepare_for_suspension()
            .map_err(|_| ServiceError::new(ServiceErrorKind::Storage))
    }
}

pub(crate) fn copy_master_key(handle: &MasterKeyHandle) -> Result<Arc<MasterKey>, ServiceError> {
    handle
        .with_key(|key| {
            let bytes = Zeroizing::new(*key.to_bytes());
            Arc::new(MasterKey::from_bytes(*bytes))
        })
        .map_err(|_| ServiceError::new(ServiceErrorKind::Crypto))
}

#[uniffi::export]
impl NativeClientHandle {
    pub fn uploads(
        self: &Arc<Self>,
        store: Arc<StoreHandle>,
        staging_root: String,
        device_id: String,
        product: String,
    ) -> Result<Arc<UploadServiceHandle>, ServiceError> {
        let service =
            UploadService::new(self.client.clone(), store.store.clone(), staging_root).map_err(map_client_error)?;
        Ok(Arc::new(UploadServiceHandle {
            root: self.clone(),
            service: Arc::new(service),
            store,
            device_id,
            product,
        }))
    }

    pub fn downloads(
        self: &Arc<Self>,
        store: Arc<StoreHandle>,
        cache_root: String,
        cache_limit_bytes: u64,
        memory_class: String,
    ) -> Result<Arc<DownloadServiceHandle>, ServiceError> {
        let budget = MemoryBudget::for_class_code(&memory_class)
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let service = DownloadService::new(
            self.client.clone(),
            store.store.clone(),
            cache_root,
            cache_limit_bytes,
            budget,
        )
        .map_err(map_client_error)?;
        Ok(Arc::new(DownloadServiceHandle {
            root: self.clone(),
            service: Arc::new(service),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn thumbnails(
        self: &Arc<Self>,
        store: Arc<StoreHandle>,
        codec: Box<dyn ImageCodecCallback>,
        cache_root: String,
        cache_limit_bytes: u64,
        platform_name: String,
        device_id: String,
        product: String,
    ) -> Result<Arc<ThumbnailServiceHandle>, ServiceError> {
        let codec: Arc<dyn ImageCodec> = Arc::new(ImageCodecAdapter { callback: codec });
        let service = ThumbnailService::new(
            self.client.clone(),
            store.store.clone(),
            codec,
            cache_root,
            cache_limit_bytes,
            platform(&platform_name),
        )
        .map_err(map_client_error)?;
        Ok(Arc::new(ThumbnailServiceHandle {
            root: self.clone(),
            service: Arc::new(service),
            store,
            device_id,
            product,
        }))
    }

    pub fn shares(self: &Arc<Self>) -> Arc<ShareServiceHandle> {
        Arc::new(ShareServiceHandle { root: self.clone() })
    }

    pub fn devices(self: &Arc<Self>) -> Arc<DeviceServiceHandle> {
        Arc::new(DeviceServiceHandle { root: self.clone() })
    }

    pub fn contacts(self: &Arc<Self>, store: Arc<StoreHandle>) -> Arc<ContactServiceHandle> {
        Arc::new(ContactServiceHandle {
            root: self.clone(),
            store,
        })
    }

    pub fn settings(self: &Arc<Self>, store: Arc<StoreHandle>) -> Arc<SettingsServiceHandle> {
        Arc::new(SettingsServiceHandle {
            root: self.clone(),
            store,
        })
    }

    pub fn sync(
        self: &Arc<Self>,
        store_path: String,
        device_id: String,
    ) -> Result<Arc<SyncServiceHandle>, ServiceError> {
        let store = Store::open(store_path).map_err(map_client_error)?;
        let engine = beebeeb_client::sync::SyncEngine::with_store_backed(device_id, store).map_err(map_client_error)?;
        Ok(Arc::new(SyncServiceHandle {
            root: self.clone(),
            engine: Mutex::new(engine),
        }))
    }
}
