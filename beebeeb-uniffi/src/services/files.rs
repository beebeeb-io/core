use super::*;

#[derive(Debug, Clone, uniffi::Record)]
pub struct FileData {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub mime_type: Option<String>,
    pub is_folder: bool,
    pub is_trashed: bool,
    pub size_bytes: u64,
    pub managed_by: Option<String>,
    pub storage_country: Option<String>,
}

impl From<&FileRecord> for FileData {
    fn from(value: &FileRecord) -> Self {
        Self {
            id: value.id.clone(),
            parent_id: value.parent_id.clone(),
            name: value.name.clone(),
            mime_type: value.mime_type.clone(),
            is_folder: value.is_folder,
            is_trashed: value.is_trashed,
            size_bytes: value.size_bytes,
            managed_by: value.managed_by.clone(),
            storage_country: value.storage_country.clone(),
        }
    }
}

#[derive(uniffi::Object)]
pub struct FilePageHandle {
    pub(crate) page: FileRecordPage,
}

#[uniffi::export]
impl FilePageHandle {
    pub fn records(&self) -> Vec<FileData> {
        self.page.files.iter().map(FileData::from).collect()
    }

    pub fn next_cursor(&self) -> Option<String> {
        self.page.next_cursor.clone()
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SearchResultData {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub is_folder: bool,
    pub mime_type: Option<String>,
}

#[derive(uniffi::Object)]
pub struct SearchServiceHandle {
    pub(crate) service: Arc<SearchService>,
}

#[uniffi::export]
impl SearchServiceHandle {
    #[uniffi::constructor]
    pub fn new(capacity: u32) -> Arc<Self> {
        Arc::new(Self {
            service: Arc::new(SearchService::new(capacity as usize)),
        })
    }

    pub fn index_page(&self, page: &FilePageHandle) {
        for record in &page.page.files {
            self.service.upsert(record.clone());
        }
    }

    pub fn remove(&self, id: String) {
        self.service.remove(&id);
    }

    pub fn query(&self, query: String) -> Vec<SearchResultData> {
        self.service
            .query(&query)
            .into_iter()
            .map(|value| SearchResultData {
                id: value.id,
                name: value.name,
                parent_id: value.parent_id,
                is_folder: value.is_folder,
                mime_type: value.mime_type,
            })
            .collect()
    }
}

#[derive(uniffi::Object)]
pub struct SyncServiceHandle {
    pub(super) root: Arc<NativeClientHandle>,
    pub(super) engine: Mutex<beebeeb_client::sync::SyncEngine>,
}

#[uniffi::export]
impl SyncServiceHandle {
    /// First sync, and the authoritative rebase used after an expired local
    /// change window.
    pub fn refresh_snapshot(&self) -> Result<(), ServiceError> {
        let session = self.root.session()?;
        let mut engine = self.engine.lock().map_err(|_| ServiceError::unavailable())?;
        self.root
            .runtime
            .block_on(self.root.client.refresh_sync_snapshot(&session, &mut engine))
            .map_err(map_client_error)
    }

    pub fn recover_gap(&self, catch_up_limit: u16) -> Result<(), ServiceError> {
        let session = self.root.session()?;
        let mut engine = self.engine.lock().map_err(|_| ServiceError::unavailable())?;
        self.root
            .runtime
            .block_on(self.root.client.recover_sync_gap(&session, &mut engine, catch_up_limit))
            .map_err(map_client_error)
    }

    pub fn catch_up(&self, limit: u16) -> Result<(), ServiceError> {
        let session = self.root.session()?;
        let mut engine = self.engine.lock().map_err(|_| ServiceError::unavailable())?;
        self.root
            .runtime
            .block_on(self.root.client.catch_up_sync(&session, &mut engine, limit))
            .map_err(map_client_error)
    }

    pub fn foreground_once(&self, catch_up_limit: u16) -> Result<bool, ServiceError> {
        let session = self.root.session()?;
        let mut engine = self.engine.lock().map_err(|_| ServiceError::unavailable())?;
        self.root
            .runtime
            .block_on(
                self.root
                    .client
                    .foreground_sync_once(&session, &mut engine, catch_up_limit),
            )
            .map_err(map_client_error)
    }
}

#[derive(uniffi::Object)]
pub struct FileServiceHandle {
    pub(super) root: Arc<NativeClientHandle>,
}

#[uniffi::export]
impl FileServiceHandle {
    pub fn list_page(
        &self,
        parent_id: Option<String>,
        trashed: bool,
        cursor: Option<String>,
        limit: u16,
    ) -> Result<Arc<FilePageHandle>, ServiceError> {
        let session = self.root.session()?;
        let page = self
            .root
            .runtime
            .block_on(self.root.client.list_file_records_page(
                &session,
                parent_id.as_deref(),
                trashed,
                cursor.as_deref(),
                limit,
            ))
            .map_err(map_client_error)?;
        Ok(Arc::new(FilePageHandle { page }))
    }

    pub fn get(&self, id: String) -> Result<FileData, ServiceError> {
        let session = self.root.session()?;
        let record = self
            .root
            .runtime
            .block_on(self.root.client.get_file_record(&session, &id))
            .map_err(map_client_error)?;
        Ok(FileData::from(&record))
    }

    pub fn create_folder(&self, name: String, parent_id: Option<String>) -> Result<FileData, ServiceError> {
        let session = self.root.session()?;
        let record = self
            .root
            .runtime
            .block_on(self.root.client.create_folder(&session, &name, parent_id))
            .map_err(map_client_error)?;
        Ok(FileData::from(&record))
    }

    pub fn rename(&self, page: &FilePageHandle, id: String, new_name: String) -> Result<FileData, ServiceError> {
        let session = self.root.session()?;
        let entry = page
            .page
            .files
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let record = self
            .root
            .runtime
            .block_on(self.root.client.rename_entry(&session, entry.wire(), &new_name))
            .map_err(map_client_error)?;
        Ok(FileData::from(&record))
    }

    pub fn move_entry(
        &self,
        page: &FilePageHandle,
        id: String,
        parent_id: Option<String>,
    ) -> Result<FileData, ServiceError> {
        let session = self.root.session()?;
        let entry = page
            .page
            .files
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let record = self
            .root
            .runtime
            .block_on(self.root.client.move_entry(&session, entry.wire(), parent_id))
            .map_err(map_client_error)?;
        Ok(FileData::from(&record))
    }

    pub fn trash(&self, id: String) -> Result<(), ServiceError> {
        self.root.session()?;
        let entry = self
            .root
            .runtime
            .block_on(self.root.client.get_file(&id))
            .map_err(map_client_error)?;
        self.root
            .runtime
            .block_on(self.root.client.trash_entry(&entry))
            .map_err(map_client_error)
    }

    pub fn restore(&self, id: String) -> Result<(), ServiceError> {
        self.root.session()?;
        let entry = self
            .root
            .runtime
            .block_on(self.root.client.get_file(&id))
            .map_err(map_client_error)?;
        self.root
            .runtime
            .block_on(self.root.client.restore_entry(&entry))
            .map_err(map_client_error)
    }

    pub fn restore_version(
        &self,
        store: Arc<StoreHandle>,
        file_id: String,
        version_id: String,
    ) -> Result<Option<u64>, ServiceError> {
        let session = self.root.session()?;
        self.root
            .runtime
            .block_on(
                self.root
                    .client
                    .restore_version(&session, &store.store, &file_id, &version_id),
            )
            .map(|result| result.counter)
            .map_err(map_client_error)
    }

    pub fn delete_forever(&self, id: String) -> Result<(), ServiceError> {
        self.root.session()?;
        let entry = self
            .root
            .runtime
            .block_on(self.root.client.get_file(&id))
            .map_err(map_client_error)?;
        self.root
            .runtime
            .block_on(self.root.client.delete_entry_forever(&entry))
            .map_err(map_client_error)
    }
}
