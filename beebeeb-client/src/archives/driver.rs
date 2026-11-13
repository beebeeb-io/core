//! The extraction run's task: it steps core's `Extraction`, answers its
//! reads through the `RangeReader`, creates folders, stages each file as
//! `archive-<instance>-<run>-<node>.bbtmp` (0600) and hands it to the upload
//! queue on `FileEnd`; every staged file is deleted when its upload ends,
//! when the entry is skipped, and when the run stops, fails or is dropped.

use super::*;

/// A file being staged or uploaded.
struct Staged {
    node: u32,
    path: PathBuf,
    file: Option<File>,
    name: String,
    parent: Option<String>,
    bytes: u64,
}

impl Staged {
    fn delete(&mut self) {
        self.file = None;
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for Staged {
    /// A staged file never outlives its record (a run dropped with its
    /// runtime included).
    fn drop(&mut self) {
        self.delete();
    }
}

pub(super) struct Driver {
    inner: Arc<Inner>,
    archive_id: ArchiveId,
    archive: Arc<Mutex<Archive>>,
    run: ExtractionId,
    identity: ArchiveIdentity,
    /// The folder the extraction lands in (`None`: the top of the drive).
    destination: Option<String>,
    reader: RangeReader,
    control: mpsc::UnboundedReceiver<Control>,
    options: ExtractOptions,
    /// Created folders: plan node → remote id.
    folders: HashMap<u32, String>,
    /// Files being staged, by plan node.
    staged: HashMap<u32, Staged>,
    /// Files handed to the upload queue, by upload id.
    uploading: HashMap<i64, Staged>,
    /// Staged plaintext not yet uploaded.
    staged_bytes: u64,
}

impl Driver {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        inner: Arc<Inner>,
        archive_id: ArchiveId,
        archive: Arc<Mutex<Archive>>,
        run: ExtractionId,
        identity: ArchiveIdentity,
        destination: Option<String>,
        reader: RangeReader,
        control: mpsc::UnboundedReceiver<Control>,
        options: ExtractOptions,
    ) -> Self {
        Self {
            inner,
            archive_id,
            archive,
            run,
            identity,
            destination,
            reader,
            control,
            options,
            folders: HashMap::new(),
            staged: HashMap::new(),
            uploading: HashMap::new(),
            staged_bytes: 0,
        }
    }

    /// Act on the extraction's state while the run's lock is held.
    fn with_run<T>(&self, act: impl FnOnce(&mut Run) -> T) -> Option<T> {
        let mut archive = self.archive.lock().ok()?;
        match &mut archive.phase {
            Phase::Running(run) if run.id == self.run => Some(act(run)),
            _ => None,
        }
    }

    fn fail(&self, reason: FailReason) {
        self.with_run(|run| run.extraction.run_failed(reason));
    }

    pub(super) async fn drive(mut self) {
        // What lands must be what was listed (a new version since is Changed).
        if self.inner.same_version(&self.identity).await == Some(false) {
            self.fail(FailReason::Changed);
        }
        loop {
            while let Ok(message) = self.control.try_recv() {
                self.handle(message);
            }
            let stopping = self.with_run(|run| run.extraction.is_stopping()).unwrap_or(true);
            let ahead = self.inner.staging_ahead_bytes.load(Ordering::Relaxed);
            if !stopping && self.staged_bytes > ahead && !self.uploading.is_empty() {
                // Backpressure: wait for uploads before staging more.
                if !self.wait().await {
                    return;
                }
                continue;
            }
            let Some(step) = self.with_run(|run| run.extraction.step()) else {
                self.cleanup_all();
                return;
            };
            match step {
                ExtractStep::NeedBytes(range) => self.read(range).await,
                ExtractStep::NeedPassword { wrong, .. } => {
                    // Shown once per question: an unrelated wake (an upload's
                    // progress) asks the same question again, silently.
                    let asked = self.with_run(|run| run.asking.replace(wrong) != Some(wrong));
                    if asked == Some(true) {
                        self.inner.emit_model(self.archive_id, &self.archive);
                    }
                    if !self.wait().await {
                        return;
                    }
                }
                ExtractStep::CreateFolder { node, parent, name } => self.create_folder(node, parent, &name).await,
                ExtractStep::FileBegin { node, parent, name, .. } => self.begin(node, parent, name),
                ExtractStep::FileData { node, bytes } => self.write(node, &bytes),
                ExtractStep::FileEnd { node } => self.publish(node),
                ExtractStep::FileSkipped { node, .. } => {
                    if let Some(mut staged) = self.staged.remove(&node) {
                        self.staged_bytes = self.staged_bytes.saturating_sub(staged.bytes);
                        staged.delete();
                    }
                }
                ExtractStep::Progress(progress) => {
                    self.with_run(|run| run.progress = Some(progress));
                    self.inner.emit_model(self.archive_id, &self.archive);
                }
                ExtractStep::Waiting => {
                    if !self.wait().await {
                        return;
                    }
                }
                ExtractStep::Finished(summary) => {
                    self.finish(summary);
                    return;
                }
            }
        }
    }

    /// Wait for the next message. `false`: every sender is gone (the
    /// service's own drop sends `Cancel` first, so this is a backstop).
    async fn wait(&mut self) -> bool {
        match self.control.recv().await {
            Some(message) => {
                self.handle(message);
                true
            }
            None => {
                self.cleanup_all();
                false
            }
        }
    }

    fn handle(&mut self, message: Control) {
        match message {
            Control::Cancel => {
                self.with_run(|run| run.extraction.cancel());
            }
            Control::Password(password) => {
                self.with_run(|run| {
                    run.asking = None;
                    run.extraction.supply_password(password);
                });
            }
            Control::Upload(UploadEvent::Changed { id, state }) => self.upload_changed(id, state),
            Control::Upload(UploadEvent::QuotaFull { id }) => {
                if self.uploading.contains_key(&id) {
                    self.upload_changed(id, TransferState::Failed);
                    self.fail(FailReason::StorageFull);
                }
            }
            Control::Upload(_) => {}
            Control::Lagged => self.reconcile(),
        }
    }

    fn upload_changed(&mut self, id: i64, state: TransferState) {
        let ok = match state {
            TransferState::Succeeded => true,
            TransferState::Failed | TransferState::Cancelled => false,
            TransferState::Queued | TransferState::Running | TransferState::Paused => return,
        };
        let Some(mut staged) = self.uploading.remove(&id) else {
            return;
        };
        self.staged_bytes = self.staged_bytes.saturating_sub(staged.bytes);
        staged.delete();
        let node = staged.node;
        self.with_run(|run| run.extraction.upload_finished(node, ok));
    }

    /// Read the upload queue's states for this run's uploads again.
    fn reconcile(&mut self) {
        let Ok(list) = self.inner.uploads.list_inner() else {
            return;
        };
        for summary in list {
            if self.uploading.contains_key(&summary.id) {
                self.upload_changed(summary.id, summary.state);
            }
        }
    }

    async fn read(&mut self, range: ByteRange) {
        // Each read first asks whether the archive got a new version.
        if self.inner.same_version(&self.identity).await == Some(false) {
            self.fail(FailReason::Changed);
            return;
        }
        match fetch(&self.inner.downloads, &mut self.reader, range).await {
            Ok((offset, bytes)) => {
                let supplied = self.with_run(|run| run.extraction.source_mut().supply(offset, bytes).is_ok());
                if supplied == Some(false) {
                    self.fail(FailReason::Damaged);
                }
            }
            Err(DownloadServiceError::Truncated | DownloadServiceError::VersionRollback) => {
                self.fail(FailReason::Damaged)
            }
            Err(_) => self.fail(FailReason::Network),
        }
    }

    async fn create_folder(&mut self, node: u32, parent: Option<u32>, name: &str) {
        let parent = match parent {
            None => self.destination.clone(),
            Some(parent) => match self.folders.get(&parent) {
                Some(id) => Some(id.clone()),
                None => {
                    self.fail(FailReason::Network);
                    return;
                }
            },
        };
        match self.inner.create_folder(name, parent).await {
            Ok(remote) => {
                self.folders.insert(node, remote.clone());
                self.with_run(|run| run.extraction.folder_created(node, remote));
            }
            Err(ArchiveServiceError::Client(ClientError::Api(beebeeb_api::ApiError::Server(server))))
                if server.status == 409 && server.is_code("name_conflict") =>
            {
                self.with_run(|run| run.extraction.folder_name_taken(node));
            }
            Err(error) => self.fail(fail_reason(&error)),
        }
    }

    fn begin(&mut self, node: u32, parent: Option<u32>, name: String) {
        let parent = match parent {
            None => self.destination.clone(),
            Some(parent) => match self.folders.get(&parent) {
                Some(id) => Some(id.clone()),
                // Never into another folder: the run fails as create_folder does.
                None => {
                    self.fail(FailReason::Network);
                    return;
                }
            },
        };
        let path = self
            .inner
            .temp_root
            .join(format!("archive-{}-{}-{node}.bbtmp", self.inner.instance, self.run.0));
        match create_private(&path) {
            Ok(file) => {
                self.staged.insert(
                    node,
                    Staged {
                        node,
                        path,
                        file: Some(file),
                        name,
                        parent,
                        bytes: 0,
                    },
                );
            }
            // Nothing was created (`create_new`): the name is not ours to delete.
            Err(_) => self.fail(FailReason::StorageFull),
        }
    }

    fn write(&mut self, node: u32, bytes: &[u8]) {
        let Some(staged) = self.staged.get_mut(&node) else {
            return;
        };
        let written = staged.file.as_mut().map(|file| file.write_all(bytes));
        if matches!(written, Some(Ok(()))) {
            staged.bytes = staged.bytes.saturating_add(bytes.len() as u64);
            self.staged_bytes = self.staged_bytes.saturating_add(bytes.len() as u64);
        } else {
            // The device is full or the temp root is gone.
            self.fail(FailReason::StorageFull);
        }
    }

    /// The entry verified: hand the staged file to the upload queue.
    fn publish(&mut self, node: u32) {
        let Some(mut staged) = self.staged.remove(&node) else {
            self.with_run(|run| run.extraction.upload_finished(node, false));
            return;
        };
        let flushed = staged.file.take().map(|file| file.sync_all());
        if !matches!(flushed, Some(Ok(()))) {
            self.staged_bytes = self.staged_bytes.saturating_sub(staged.bytes);
            staged.delete();
            self.with_run(|run| run.extraction.upload_finished(node, false));
            self.fail(FailReason::StorageFull);
            return;
        }
        let mime = beebeeb_core::media::guess_mime_type(&staged.name).map(str::to_owned);
        let mut request = UploadRequest::new(&staged.path, staged.name.clone(), mime, staged.parent.clone());
        request.wifi_only = self.options.wifi_only;
        if let Some(limit) = self.options.upload_disk_limit {
            request.disk_limit = limit;
        }
        let queued = transfer_now_ms().and_then(|now| self.inner.uploads.enqueue(request, now));
        match queued {
            Ok(id) => {
                self.uploading.insert(id, staged);
            }
            Err(error) => {
                self.staged_bytes = self.staged_bytes.saturating_sub(staged.bytes);
                staged.delete();
                self.with_run(|run| run.extraction.upload_finished(node, false));
                if let UploadServiceError::Client(error) = error {
                    self.fail(fail_reason(&ArchiveServiceError::Client(error)));
                }
            }
        }
    }

    /// The run ended: stop this run's queued uploads, count any that finished
    /// meanwhile, delete every staged file and report.
    fn finish(&mut self, mut summary: ExtractSummary) {
        let now = transfer_now_ms().unwrap_or(0);
        let mut landed = 0u32;
        let pending: Vec<i64> = self.uploading.keys().copied().collect();
        let states: HashMap<i64, TransferState> = self
            .inner
            .uploads
            .list()
            .map(|list| list.into_iter().map(|s| (s.id, s.state)).collect())
            .unwrap_or_default();
        for id in pending {
            if states.get(&id) == Some(&TransferState::Succeeded) {
                landed += 1;
            } else if let Ok(plan) = self.inner.uploads.cancel(id, now) {
                for path in plan.delete_files {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        // An upload that finished between the run's end and this moment is
        // in the folder: the summary says exactly what is there.
        summary.files_done = summary.files_done.saturating_add(landed);
        self.cleanup_all();
        self.with_run(|run| {
            run.progress = None;
            run.asking = None;
            run.summary = Some(summary.clone());
        });
        if let Ok(mut runs) = self.inner.runs.lock() {
            runs.remove(&self.run);
        }
        self.inner.emit_model(self.archive_id, &self.archive);
        self.inner.emit(ArchiveEvent::Finished { id: self.run, summary });
    }

    fn cleanup_all(&mut self) {
        for (_, mut staged) in self.staged.drain() {
            staged.delete();
        }
        for (_, mut staged) in self.uploading.drain() {
            staged.delete();
        }
        self.staged_bytes = 0;
    }
}

/// Why a run fails when the server or the account refuses a step.
fn fail_reason(error: &ArchiveServiceError) -> FailReason {
    match error {
        ArchiveServiceError::Client(ClientError::Api(beebeeb_api::ApiError::Server(server))) => {
            if server.is_code("quota_exceeded") || server.is_trial_cap() || server.status == 507 {
                FailReason::StorageFull
            } else if matches!(server.status, 402 | 403 | 423) {
                FailReason::AccountBlocked
            } else {
                FailReason::Network
            }
        }
        ArchiveServiceError::Plan(_) | ArchiveServiceError::Destination => FailReason::AccountBlocked,
        _ => FailReason::Network,
    }
}

/// A staged file: readable by this user only (0600 on Unix).
fn create_private(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
