//! The native archive service (archives spec §5.2): the iOS app's driver for
//! core's archive session, planner and extraction.
//!
//! Core decides everything (what is listed, every name, when a file may be
//! published, how a run ends, every word); this service only carries the steps
//! out. It reads the archive through [`DownloadService::read_with`] (core's
//! `RangeOpener`, v1 and v2), creates folders, stages each extracted file in
//! its temp root and hands it to the [`UploadService`] only on `FileEnd`, after
//! the entry's own check passed. A staged file is deleted when its upload
//! finishes, fails or is cancelled, when the entry is skipped, and when the run
//! stops or fails.
//!
//! Listing and extraction run as tasks on the caller's Tokio runtime (the app's
//! multi-thread runtime; archives never run in the File Provider extension).
//! Every state change is an [`ArchiveEvent`].

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use beebeeb_api::routes::files as api;
use beebeeb_core::archives::limits::{MAX_CENTRAL_DIRECTORY_BYTES, NATIVE_STAGING_AHEAD_BYTES};
use beebeeb_core::archives::{
    ArchiveIdentity, ArchivePassword, ArchivePlatform, ArchivePreviewModel, ArchiveRefusal, ArchiveSession, ByteRange,
    DestinationInfo, DestinationKind, EntryKind, ExtractProgress, ExtractRequest, ExtractStep, ExtractSummary,
    Extraction, FailReason, ListingState, PieceStep, PlanRefusal, PreviewInput, Selection, SessionStep, SkipReason,
    SuppliedBytes, archive_preview, plan_extraction,
};
use beebeeb_core::backup::BackupPosition;
use beebeeb_core::encrypt::decrypt_name_metadata;
use beebeeb_core::name_clash::TakenNames;
use beebeeb_store::TransferState;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::backup_guard::GuardError;
use crate::downloads::{DownloadFile, DownloadService, DownloadServiceError, RangeReader, range_read_cap};
use crate::files::{FILE_LIST_PAGE_CAP, FileServiceError};
use crate::uploads::{UploadEvent, UploadRequest, UploadService, UploadServiceError, transfer_now_ms};
use crate::{Client, ClientError};

mod driver;

use driver::Driver;

/// An open archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArchiveId(pub u64);

/// One extraction run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtractionId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveEvent {
    /// The archive's screen changed (reading, listed, refused, asking for the
    /// password, progress, finished). The model shows the archive's top
    /// folder; [`ArchiveService::preview`] gives any other folder.
    Model {
        id: ArchiveId,
        model: ArchivePreviewModel,
    },
    /// The archive's bytes could not be read (the network or the download
    /// failed): nothing was listed. Open it again to retry.
    ReadFailed {
        id: ArchiveId,
    },
    Finished {
        id: ExtractionId,
        summary: ExtractSummary,
    },
}

/// Where an extraction lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractDestination {
    /// The folder the archive is in ("Extract").
    NextToArchive,
    /// A folder the person chose ("Extract to…"); `None` is the top of the drive.
    Folder(Option<String>),
}

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub selection: Selection,
    pub destination: ExtractDestination,
    /// Free disk on this device (the app knows it; staged files need room
    /// for the largest file).
    pub device_free_bytes: Option<u64>,
    /// The person's upload settings, applied to every extracted file.
    pub wifi_only: bool,
    /// The upload queue's per-file staging limit; `None` keeps its default.
    pub upload_disk_limit: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveServiceError {
    #[error("no archive is open under this id")]
    UnknownArchive,
    #[error("the archive is still being read")]
    Reading,
    #[error("the archive could not be read")]
    ReadFailed,
    #[error("the archive cannot be listed")]
    Refused(ArchiveRefusal),
    #[error("an extraction holds this archive; open it again")]
    Busy,
    /// Nothing was written; `PlanRefusal::text` has core's words.
    #[error("{}", .0.text().text)]
    Plan(PlanRefusal),
    #[error("this entry is protected by a password")]
    PasswordNeeded,
    #[error("the password is wrong")]
    WrongPassword,
    #[error("this entry is damaged")]
    Corrupt,
    #[error("this entry is too large to open here")]
    TooLarge,
    #[error("this entry cannot be opened")]
    Skipped(SkipReason),
    #[error("the archive has no such entry")]
    NoEntry,
    #[error("where the destination is cannot be told")]
    Destination,
    #[error("archive state is unavailable")]
    State,
    #[error(transparent)]
    Download(#[from] DownloadServiceError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

impl From<FileServiceError> for ArchiveServiceError {
    fn from(error: FileServiceError) -> Self {
        match error {
            FileServiceError::Client(error) => Self::Client(error),
            FileServiceError::Protected(_) => Self::Plan(PlanRefusal::Backups),
            _ => Self::State,
        }
    }
}

/// What the run's task is told.
enum Control {
    Upload(UploadEvent),
    /// Upload events were missed: read the queue's states again.
    Lagged,
    Cancel,
    Password(ArchivePassword),
}

type Source = SuppliedBytes;

struct Run {
    id: ExtractionId,
    extraction: Extraction<Source>,
    progress: Option<ExtractProgress>,
    /// `Some(wrong)` while the password is asked for.
    asking: Option<bool>,
    summary: Option<ExtractSummary>,
}

enum Phase {
    Reading(ArchiveSession<Source>),
    Listed(ArchiveSession<Source>),
    Refused(ArchiveRefusal),
    ReadFailed,
    Running(Box<Run>),
    /// Between two phases, while the lock is held.
    Moving,
}

struct Archive {
    file: DownloadFile,
    name: String,
    parent_id: Option<String>,
    destination: DestinationKind,
    phase: Phase,
    /// The reader `open_entry` keeps between calls.
    reader: Option<RangeReader>,
    listing: Option<JoinHandle<()>>,
}

/// Temp roots with a live service in this process. A second service on
/// one root would delete the first one's staged files and cancel its
/// uploads, so it is refused until the first is dropped.
static LIVE_ROOTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

struct Inner {
    client: Arc<Client>,
    downloads: Arc<DownloadService>,
    uploads: Arc<UploadService>,
    temp_root: PathBuf,
    /// 128 random bits in every staged name: a name never repeats across
    /// processes, so an upload record an earlier process left can never
    /// pick up this process's file.
    instance: String,
    /// Staged plaintext allowed ahead of the uploads.
    staging_ahead_bytes: AtomicU64,
    platform: ArchivePlatform,
    archives: Mutex<HashMap<ArchiveId, Arc<Mutex<Archive>>>>,
    runs: Mutex<HashMap<ExtractionId, mpsc::UnboundedSender<Control>>>,
    next_id: AtomicU64,
    events: broadcast::Sender<ArchiveEvent>,
}

pub struct ArchiveService {
    inner: Arc<Inner>,
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, ArchiveServiceError> {
    mutex.lock().map_err(|_| ArchiveServiceError::State)
}

/// A staged file's name: `archive-<instance>-<run>-<node>.bbtmp`.
fn is_staged_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("archive-") && name.ends_with(".bbtmp"))
}

impl ArchiveService {
    /// The service owns `temp_root`; one live service per root in a
    /// process (a second one is refused with `State`). What an earlier
    /// process left there (an extraction does not outlive the app) goes
    /// now: its queued uploads are cancelled, then its staged files are
    /// deleted. Other files in `temp_root` are left alone.
    pub fn new(
        client: Arc<Client>,
        downloads: Arc<DownloadService>,
        uploads: Arc<UploadService>,
        temp_root: PathBuf,
        platform: ArchivePlatform,
    ) -> Result<Self, ArchiveServiceError> {
        std::fs::create_dir_all(&temp_root).map_err(|_| ArchiveServiceError::State)?;
        let canonical = temp_root.canonicalize().map_err(|_| ArchiveServiceError::State)?;
        {
            let mut live = lock(&LIVE_ROOTS)?;
            if live.contains(&canonical) {
                return Err(ArchiveServiceError::State);
            }
            live.push(canonical.clone());
        }
        let now = transfer_now_ms().unwrap_or(0);
        for root in [&temp_root, &canonical] {
            let _ = uploads.cancel_sources_under(root, now);
        }
        if let Ok(entries) = std::fs::read_dir(&canonical) {
            for path in entries.flatten().map(|entry| entry.path()) {
                if path.is_file() && is_staged_name(&path) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                downloads,
                uploads,
                temp_root: canonical,
                instance: uuid::Uuid::new_v4().simple().to_string(),
                staging_ahead_bytes: AtomicU64::new(NATIVE_STAGING_AHEAD_BYTES),
                platform,
                archives: Mutex::new(HashMap::new()),
                runs: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
                events,
            }),
        })
    }

    pub fn observe(&self) -> broadcast::Receiver<ArchiveEvent> {
        self.inner.events.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn set_staging_ahead_for_test(&self, bytes: u64) {
        self.inner.staging_ahead_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Open the archive `file` (named `name`, in folder `parent_id`) and start
    /// listing it. The listing arrives as an [`ArchiveEvent::Model`].
    pub async fn open(
        &self,
        file: &DownloadFile,
        name: String,
        parent_id: Option<String>,
    ) -> Result<ArchiveId, ArchiveServiceError> {
        let reader = self.inner.downloads.range_reader(file)?;
        let id = ArchiveId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        // The source holds what the reader still needs: the central directory
        // and the chunks around it (spec §8).
        let held = MAX_CENTRAL_DIRECTORY_BYTES.saturating_add(file.chunk_size_bytes.saturating_mul(2));
        let session = ArchiveSession::open(SuppliedBytes::new(file.size_bytes, held), self.inner.platform);
        let archive = Arc::new(Mutex::new(Archive {
            file: file.clone(),
            name,
            parent_id,
            destination: DestinationKind::NextTo,
            phase: Phase::Reading(session),
            reader: None,
            listing: None,
        }));
        lock(&self.inner.archives)?.insert(id, Arc::clone(&archive));
        self.inner.emit_model(id, &archive);
        let task = tokio::spawn(list(Arc::clone(&self.inner), id, Arc::clone(&archive), reader));
        lock(&archive)?.listing = Some(task);
        Ok(id)
    }

    /// The preview of folder `folder` of the archive, with `selection` (paths
    /// as the rows name them) selected.
    pub async fn preview(
        &self,
        id: ArchiveId,
        folder: Vec<String>,
        selection: Vec<String>,
    ) -> Result<ArchivePreviewModel, ArchiveServiceError> {
        let archive = self.inner.archive(id)?;
        let archive = lock(&archive)?;
        model(&archive, self.inner.platform, &folder, &selection)
    }

    /// Plan and start extracting. A plan refusal writes nothing. A password
    /// from the preview is passed on, so the person is not asked twice.
    pub async fn extract(
        &self,
        id: ArchiveId,
        options: ExtractOptions,
        password: Option<ArchivePassword>,
    ) -> Result<ExtractionId, ArchiveServiceError> {
        let archive = self.inner.archive(id)?;
        let (file, name, archive_parent) = {
            let archive = lock(&archive)?;
            match &archive.phase {
                Phase::Listed(_) => {}
                Phase::Reading(_) | Phase::Moving => return Err(ArchiveServiceError::Reading),
                Phase::Refused(refusal) => return Err(ArchiveServiceError::Refused(*refusal)),
                Phase::ReadFailed => return Err(ArchiveServiceError::ReadFailed),
                Phase::Running(_) => return Err(ArchiveServiceError::Busy),
            }
            (archive.file.clone(), archive.name.clone(), archive.parent_id.clone())
        };
        let parent = match &options.destination {
            ExtractDestination::NextToArchive => archive_parent,
            ExtractDestination::Folder(folder) => folder.clone(),
        };
        let destination = self.inner.destination_info(parent.as_deref()).await?;
        let usage = self.inner.client.storage_usage().await?;
        let free = usage.plan_limit_bytes.saturating_sub(usage.used_bytes).max(0);
        let request = ExtractRequest {
            archive_name: name,
            selection: options.selection.clone(),
            destination,
            server_free_bytes: u64::try_from(free).unwrap_or(0),
            device_free_bytes: options.device_free_bytes,
            platform: self.inner.platform,
        };
        let reader = self.inner.downloads.range_reader(&file)?;
        let run = ExtractionId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let identity = ArchiveIdentity {
            file_id: file.file_id.clone(),
            object_version_id: file.object_version_id.clone(),
        };
        {
            let mut archive = lock(&archive)?;
            let Phase::Listed(session) = &archive.phase else {
                return Err(ArchiveServiceError::Busy);
            };
            let listing = session.listing().ok_or(ArchiveServiceError::State)?;
            let plan = plan_extraction(listing, &request).map_err(ArchiveServiceError::Plan)?;
            let Phase::Listed(session) = std::mem::replace(&mut archive.phase, Phase::Moving) else {
                return Err(ArchiveServiceError::State);
            };
            archive.phase = Phase::Running(Box::new(Run {
                id: run,
                extraction: Extraction::start(session, identity.clone(), plan, password),
                progress: None,
                asking: None,
                summary: None,
            }));
        }
        let (control, receiver) = mpsc::unbounded_channel();
        // Subscribe before the first upload is queued, so no event is missed.
        let forwarder = tokio::spawn(forward_uploads(self.inner.uploads.observe(), control.clone()));
        // The archive is Running now: a poisoned map must not strand it.
        self.inner
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(run, control);
        let driver = Driver::new(
            Arc::clone(&self.inner),
            id,
            archive,
            run,
            identity,
            parent,
            reader,
            receiver,
            options,
        );
        tokio::spawn(async move {
            driver.drive().await;
            forwarder.abort();
        });
        Ok(run)
    }

    /// The password for a run that asked for it (`ArchiveEvent::Model` in the
    /// `NeedsPassword` state).
    pub fn supply_password(&self, id: ExtractionId, password: ArchivePassword) {
        if let Ok(runs) = self.inner.runs.lock()
            && let Some(control) = runs.get(&id)
        {
            let _ = control.send(Control::Password(password));
        }
    }

    /// The bytes of one entry, for Open and Download, after the entry's own
    /// check passed. Entries larger than the platform's in-memory budget are
    /// refused (`TooLarge`).
    pub async fn open_entry(
        &self,
        id: ArchiveId,
        index: u32,
        password: Option<ArchivePassword>,
    ) -> Result<Vec<u8>, ArchiveServiceError> {
        let archive = self.inner.archive(id)?;
        let budget = self.inner.platform.budget().archive_output_bytes;
        let (mut stream, mut reader) = {
            let mut guard = lock(&archive)?;
            let Phase::Listed(session) = &guard.phase else {
                return Err(listed_error(&guard.phase));
            };
            let entry = session
                .listing()
                .and_then(|listing| listing.entries.get(index as usize))
                .ok_or(ArchiveServiceError::NoEntry)?;
            if let Some(reason) = &entry.skip {
                return Err(ArchiveServiceError::Skipped(reason.clone()));
            }
            if entry.kind != EntryKind::File {
                return Err(ArchiveServiceError::NoEntry);
            }
            if entry.size > budget {
                return Err(ArchiveServiceError::TooLarge);
            }
            if entry.cipher.is_encrypted() && password.is_none() {
                return Err(ArchiveServiceError::PasswordNeeded);
            }
            let stream = session
                .entry_stream(index, password.as_ref())
                .map_err(|_| ArchiveServiceError::NoEntry)?;
            let reader = match guard.reader.take() {
                Some(reader) => reader,
                None => self.inner.downloads.range_reader(&guard.file)?,
            };
            (stream, reader)
        };
        drop(password);
        let mut out = Vec::new();
        let result = loop {
            let step = {
                let mut guard = lock(&archive)?;
                let Phase::Listed(session) = &mut guard.phase else {
                    break Err(ArchiveServiceError::Busy);
                };
                stream.next_piece(session)
            };
            match step {
                PieceStep::Data(piece) => {
                    out.extend_from_slice(&piece);
                    if out.len() as u64 > budget {
                        break Err(ArchiveServiceError::TooLarge);
                    }
                }
                PieceStep::NeedBytes(range) => {
                    let (offset, bytes) = match fetch(&self.inner.downloads, &mut reader, range).await {
                        Ok(read) => read,
                        Err(error) => break Err(error.into()),
                    };
                    let mut guard = lock(&archive)?;
                    let Phase::Listed(session) = &mut guard.phase else {
                        break Err(ArchiveServiceError::Busy);
                    };
                    if session.source_mut().supply(offset, bytes).is_err() {
                        break Err(ArchiveServiceError::Corrupt);
                    }
                }
                PieceStep::Verified => break Ok(std::mem::take(&mut out)),
                PieceStep::WrongPassword => break Err(ArchiveServiceError::WrongPassword),
                PieceStep::Corrupt => break Err(ArchiveServiceError::Corrupt),
                PieceStep::Skipped(reason) => break Err(ArchiveServiceError::Skipped(reason)),
                PieceStep::Io(_) => break Err(ArchiveServiceError::ReadFailed),
            }
        };
        if let Ok(mut guard) = archive.lock() {
            guard.reader = Some(reader);
        }
        result
    }

    /// Stop a run. Files whose upload finished stay (A7); the others are not
    /// extracted. The run's password is wiped.
    pub fn cancel(&self, id: ExtractionId) {
        if let Ok(runs) = self.inner.runs.lock()
            && let Some(control) = runs.get(&id)
        {
            let _ = control.send(Control::Cancel);
        }
    }

    /// Close the archive: its listing stops, a run on it stops, and every
    /// password it holds is wiped.
    pub fn close(&self, id: ArchiveId) {
        let Some(archive) = self.inner.archives.lock().ok().and_then(|mut map| map.remove(&id)) else {
            return;
        };
        let Ok(mut archive) = archive.lock() else {
            return;
        };
        if let Some(task) = archive.listing.take() {
            task.abort();
        }
        if let Phase::Running(run) = &mut archive.phase {
            run.extraction.cancel();
            self.cancel(run.id);
        }
        archive.reader = None;
    }
}

impl Drop for ArchiveService {
    /// Runs end with their service: each stops, cancels its queued uploads
    /// and deletes what it staged; listings stop; the root is free again.
    fn drop(&mut self) {
        if let Ok(archives) = self.inner.archives.lock() {
            for archive in archives.values() {
                if let Ok(mut archive) = archive.lock()
                    && let Some(task) = archive.listing.take()
                {
                    task.abort();
                }
            }
        }
        if let Ok(runs) = self.inner.runs.lock() {
            for control in runs.values() {
                let _ = control.send(Control::Cancel);
            }
        }
        if let Ok(mut live) = LIVE_ROOTS.lock() {
            live.retain(|root| *root != self.inner.temp_root);
        }
    }
}

fn listed_error(phase: &Phase) -> ArchiveServiceError {
    match phase {
        Phase::Reading(_) | Phase::Moving => ArchiveServiceError::Reading,
        Phase::Refused(refusal) => ArchiveServiceError::Refused(*refusal),
        Phase::ReadFailed => ArchiveServiceError::ReadFailed,
        Phase::Running(_) | Phase::Listed(_) => ArchiveServiceError::Busy,
    }
}

fn model(
    archive: &Archive,
    platform: ArchivePlatform,
    folder: &[String],
    selection: &[String],
) -> Result<ArchivePreviewModel, ArchiveServiceError> {
    let mut input = PreviewInput {
        archive_name: &archive.name,
        listing: ListingState::Reading,
        folder,
        selection,
        platform,
        destination: archive.destination,
        password: None,
        progress: None,
        summary: None,
        plan: None,
    };
    match &archive.phase {
        Phase::Reading(_) | Phase::Moving => {}
        Phase::Listed(session) => {
            input.listing = ListingState::Listed(session.listing().ok_or(ArchiveServiceError::State)?);
        }
        Phase::Refused(refusal) => input.listing = ListingState::Refused(*refusal),
        Phase::ReadFailed => return Err(ArchiveServiceError::ReadFailed),
        Phase::Running(run) => {
            input.listing = ListingState::Listed(run.extraction.listing().ok_or(ArchiveServiceError::State)?);
            input.plan = Some(run.extraction.plan());
            input.progress = run.progress.as_ref();
            input.password = run.asking;
            input.summary = run.summary.as_ref();
            if run.asking.is_none() && run.progress.is_none() && run.summary.is_none() {
                // Started, nothing reported yet: show the run at zero.
                return Ok(archive_preview(&PreviewInput {
                    progress: Some(&ExtractProgress {
                        files_done: 0,
                        files_total: run.extraction.plan().totals.files,
                        bytes_done: 0,
                        bytes_total: run.extraction.plan().totals.bytes,
                        current: String::new(),
                    }),
                    ..input
                }));
            }
        }
    }
    Ok(archive_preview(&input))
}

impl Inner {
    fn archive(&self, id: ArchiveId) -> Result<Arc<Mutex<Archive>>, ArchiveServiceError> {
        lock(&self.archives)?
            .get(&id)
            .cloned()
            .ok_or(ArchiveServiceError::UnknownArchive)
    }

    fn emit(&self, event: ArchiveEvent) {
        let _ = self.events.send(event);
    }

    fn emit_model(&self, id: ArchiveId, archive: &Mutex<Archive>) {
        let Ok(archive) = archive.lock() else {
            return;
        };
        match model(&archive, self.platform, &[], &[]) {
            Ok(model) => self.emit(ArchiveEvent::Model { id, model }),
            Err(_) => self.emit(ArchiveEvent::ReadFailed { id }),
        }
    }

    /// Where an extraction into `parent` lands: its decrypted sibling names,
    /// its place relative to Backups (read from the server, never by name).
    async fn destination_info(&self, parent: Option<&str>) -> Result<DestinationInfo, ArchiveServiceError> {
        let backup_position = match parent {
            None => BackupPosition::Outside,
            Some(parent) => match self.client.backup_depth(parent).await {
                Ok(depth) => BackupPosition::at_depth(depth, ""),
                Err(GuardError::Client(error)) => return Err(error.into()),
                Err(_) => return Err(ArchiveServiceError::Destination),
            },
        };
        Ok(DestinationInfo {
            siblings: self.sibling_names(parent).await?,
            backup_position: Some(backup_position),
            // The native app extracts within the person's own drive; a
            // Backups destination is refused above.
            writable: true,
        })
    }

    async fn sibling_names(&self, parent: Option<&str>) -> Result<TakenNames, ArchiveServiceError> {
        let key = self.client.session_key()?;
        let mut taken = TakenNames::new();
        let mut cursor: Option<String> = None;
        loop {
            let page: api::ListResponse = self
                .client
                .execute(
                    &api::list_page(parent, false, cursor.as_deref(), Some(FILE_LIST_PAGE_CAP)),
                    &(),
                )
                .await?;
            for entry in &page.files {
                // A name this account cannot open still takes a name; it is
                // not known, so it cannot be avoided.
                if let Some(sealed) = entry.name_encrypted.as_deref()
                    && let Ok(metadata) = decrypt_name_metadata(key.master_key(), &entry.id, sealed)
                {
                    taken.insert(&metadata.name);
                }
            }
            match page.next_cursor {
                Some(next) if !page.files.is_empty() && cursor.as_deref() != Some(next.as_str()) => cursor = Some(next),
                _ => break,
            }
        }
        Ok(taken)
    }

    /// Create folder `name` in `parent`, sealed with this session's key. The
    /// Backups rule is asked first, as for every app create.
    async fn create_folder(&self, name: &str, parent: Option<String>) -> Result<String, ArchiveServiceError> {
        self.client
            .check_backup_create_in(parent.as_deref())
            .await
            .map_err(|error| match error {
                GuardError::Client(error) => ArchiveServiceError::Client(error),
                GuardError::Refused(_) => ArchiveServiceError::Plan(PlanRefusal::Backups),
                GuardError::Unknown => ArchiveServiceError::Destination,
            })?;
        let key = self.client.session_key()?;
        let item = beebeeb_core::item_id::NewItemId::owner(key.master_key()).map_err(|_| ArchiveServiceError::State)?;
        let name_encrypted = beebeeb_core::encrypt::encrypt_name_for_new_item(
            key.master_key(),
            &item,
            name,
            None,
            beebeeb_core::chunk_stream::ExpectedChunkFormat::Unrecorded,
        )
        .map_err(|_| ArchiveServiceError::State)?;
        let request = api::CreateFolder {
            name_encrypted,
            parent_id: parent,
            folder_id: item.as_str().to_owned(),
        };
        let entry: api::FileEntry = self.client.execute(&api::create_folder(), &request).await?;
        if entry.id != item.as_str() {
            return Err(ArchiveServiceError::State);
        }
        Ok(entry.id)
    }

    /// Whether the archive still has the version that was listed. `None`:
    /// the server's answer cannot tell (no recorded version, or no answer).
    async fn same_version(&self, identity: &ArchiveIdentity) -> Option<bool> {
        let row = self.client.get_file(&identity.file_id).await.ok()?;
        let current = row
            .extra
            .get("download_version")
            .and_then(|version| version.get("object_version_id"))
            .and_then(Value::as_str)?;
        Some(current.eq_ignore_ascii_case(&identity.object_version_id))
    }
}

/// Read `range` (widened to whole chunks, which are fetched whole anyway) for
/// the session's source.
async fn fetch(
    downloads: &DownloadService,
    reader: &mut RangeReader,
    range: ByteRange,
) -> Result<(u64, Vec<u8>), DownloadServiceError> {
    let file = reader.file();
    let stride = file.chunk_size_bytes.max(1);
    let size = file.size_bytes;
    let mut start = range.start / stride * stride;
    let mut end = range.end.div_ceil(stride).saturating_mul(stride).min(size);
    if end.saturating_sub(start) > range_read_cap(file) {
        start = range.start;
        end = range.end.min(start.saturating_add(range_read_cap(file)));
    }
    let bytes = downloads.read_with(reader, start..end).await?;
    Ok((start, bytes))
}

/// The listing task: detection, the listing, and whether Extract writes next
/// to the archive or asks for a folder (A8).
async fn list(inner: Arc<Inner>, id: ArchiveId, archive: Arc<Mutex<Archive>>, mut reader: RangeReader) {
    let parent = archive.lock().ok().and_then(|a| a.parent_id.clone());
    let destination = match parent {
        None => DestinationKind::NextTo,
        Some(parent) => match inner.client.backup_depth(&parent).await {
            Ok(None) => DestinationKind::NextTo,
            // Under Backups, or where it cannot be told: "Extract to…".
            _ => DestinationKind::ChooseFolder,
        },
    };
    if let Ok(mut archive) = archive.lock() {
        archive.destination = destination;
    }
    loop {
        let step = {
            let Ok(mut guard) = archive.lock() else {
                return;
            };
            let Phase::Reading(session) = &mut guard.phase else {
                return;
            };
            session.step()
        };
        let next = match step {
            SessionStep::NeedBytes(range) => match fetch(&inner.downloads, &mut reader, range).await {
                Ok((offset, bytes)) => {
                    let Ok(mut guard) = archive.lock() else {
                        return;
                    };
                    let Phase::Reading(session) = &mut guard.phase else {
                        return;
                    };
                    if session.source_mut().supply(offset, bytes).is_ok() {
                        continue;
                    }
                    // Bytes that differ from ones read before: the file changed.
                    Phase::Refused(ArchiveRefusal::Damaged)
                }
                Err(_) => Phase::ReadFailed,
            },
            SessionStep::Listed => Phase::Moving,
            SessionStep::Refused(refusal) => Phase::Refused(refusal),
            SessionStep::Io(_) => Phase::ReadFailed,
        };
        if let Ok(mut guard) = archive.lock() {
            let Phase::Reading(session) = std::mem::replace(&mut guard.phase, Phase::Moving) else {
                return;
            };
            guard.phase = match next {
                Phase::Moving => Phase::Listed(session),
                other => other,
            };
            guard.reader = Some(reader);
            guard.listing = None;
        }
        inner.emit_model(id, &archive);
        return;
    }
}

async fn forward_uploads(mut events: broadcast::Receiver<UploadEvent>, control: mpsc::UnboundedSender<Control>) {
    loop {
        let message = match events.recv().await {
            Ok(event) => Control::Upload(event),
            Err(broadcast::error::RecvError::Lagged(_)) => Control::Lagged,
            Err(broadcast::error::RecvError::Closed) => return,
        };
        if control.send(message).is_err() {
            return;
        }
    }
}
