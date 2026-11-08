use super::*;

impl UploadService {
    pub fn new(
        client: Arc<Client>,
        store: Arc<Mutex<Store>>,
        staging_root: impl Into<PathBuf>,
    ) -> Result<Self, UploadServiceError> {
        let staging_root = staging_root.into();
        std::fs::create_dir_all(&staging_root).map_err(|_| UploadServiceError::State)?;
        let (events, _) = broadcast::channel(64);
        Ok(Self {
            client,
            store,
            staging_root,
            events,
            completion_handler: Mutex::new(None),
            backup_lease: Mutex::new(std::sync::Weak::new()),
        })
    }

    /// One backup service per upload service: the lease, or `None` while
    /// another backup service holds it. The lease ends when its holder is
    /// dropped. Two would steal each other's completion handler and write over
    /// each other's manifest.
    pub(crate) fn lease_backup(&self) -> Result<Option<Arc<()>>, UploadServiceError> {
        let mut lease = self.backup_lease.lock().map_err(|_| UploadServiceError::State)?;
        if lease.upgrade().is_some() {
            return Ok(None);
        }
        let held = Arc::new(());
        *lease = Arc::downgrade(&held);
        Ok(Some(held))
    }

    pub fn set_completion_handler(&self, handler: Arc<dyn UploadCompletionHandler>) -> Result<(), UploadServiceError> {
        *self.completion_handler.lock().map_err(|_| UploadServiceError::State)? = Some(handler);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        client: Arc<Client>,
        store: Arc<Mutex<Store>>,
        master_key: Arc<beebeeb_core::kdf::MasterKey>,
        staging_root: impl Into<PathBuf>,
    ) -> Result<Self, UploadServiceError> {
        client.set_session_key_for_test(master_key)?;
        Self::new(client, store, staging_root)
    }

    pub fn observe(&self) -> broadcast::Receiver<UploadEvent> {
        self.events.subscribe()
    }

    pub fn enqueue(&self, mut request: UploadRequest, now_ms: i64) -> Result<i64, UploadServiceError> {
        if request.name.is_empty() || request.disk_limit == 0 {
            return Err(UploadServiceError::Source);
        }
        let session_key = self.client.session_key()?;
        if let Some(replacement) = request.replacement.as_mut() {
            let metadata = beebeeb_core::encrypt::decrypt_file_metadata(
                session_key.master_key(),
                &replacement.file_id,
                &replacement.current_version_metadata_encrypted,
            )
            .map_err(|_| UploadServiceError::Encryption)?;
            if metadata.chunk_format != ExpectedChunkFormat::V2 {
                return Err(UploadServiceError::Encryption);
            }
            // The new version is max(remembered, served) + 1: the metadata
            // comes from the server, which could serve an older record and make
            // this version reuse a counter already seen (crypto
            // review, P3).
            let served = metadata.version.ok_or(UploadServiceError::Encryption)?.counter;
            let remembered = self
                .store
                .lock()
                .map_err(|_| UploadServiceError::State)?
                .highest_file_version(&replacement.file_id)
                .map_err(|_| UploadServiceError::State)?;
            replacement.previous_version_counter = Some(remembered.map_or(served, |highest| highest.max(served)));
        }
        let source_identity = source_identity(&request.source_path)?;
        let item_id = request
            .replacement
            .is_none()
            .then(|| NewItemId::owner(session_key.master_key()).map_err(|_| UploadServiceError::Encryption))
            .transpose()?;
        if request.replacement.as_ref().is_some_and(|replacement| {
            !matches!(
                beebeeb_core::item_id::item_class(&replacement.file_id),
                Ok(beebeeb_core::item_id::ItemClass::Owner)
            )
        }) {
            return Err(UploadServiceError::Encryption);
        }
        let file_id = match (&request.replacement, &item_id) {
            (Some(replacement), _) => replacement.file_id.clone(),
            (None, Some(item)) => item.as_str().to_owned(),
            (None, None) => return Err(UploadServiceError::Encryption),
        };
        let item_tag = item_id.as_ref().map_or_else(Vec::new, |item| item.tag().to_vec());
        let record = UploadRecord {
            source_path: request.source_path,
            source_identity,
            name: request.name,
            mime_type: request.mime_type,
            parent_id: request.parent_id,
            wifi_only: request.wifi_only,
            disk_limit: request.disk_limit,
            file_id,
            item_tag,
            session_id: None,
            chunk_size: None,
            chunk_count: None,
            planner: None,
            backup_local_identifier: request.backup_local_identifier,
            replacement: request.replacement,
            restart_intent: None,
            remote_completed: false,
            complete_name_encrypted: None,
            backup_outcome_applied: false,
        };
        let payload = encode_record(&record)?;
        let id = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .enqueue_transfer(UPLOAD_KIND, &payload, DEFAULT_MAX_ATTEMPTS, now_ms)
            .map_err(|_| UploadServiceError::State)?;
        self.emit(UploadEvent::Changed {
            id,
            state: TransferState::Queued,
        });
        Ok(id)
    }

    /// Claim and prepare the oldest upload. Initialization, scoped-token
    /// minting, v2 encryption and staging all happen here, not in the platform.
    pub async fn next_transfers(
        &self,
        limit: usize,
        network: NetworkKind,
        now_ms: i64,
    ) -> Result<Option<(i64, Vec<TransferRequest>)>, UploadServiceError> {
        if limit == 0 {
            return Ok(None);
        }
        let lease_until = now_ms.checked_add(LEASE_MS).ok_or(UploadServiceError::State)?;
        let transfer = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .claim_transfer_kind(UPLOAD_KIND, now_ms, lease_until)
            .map_err(|_| UploadServiceError::State)?;
        let Some(transfer) = transfer else {
            return Ok(None);
        };
        let mut record = match decode_record(&transfer.payload) {
            Ok(record) => record,
            Err(error) => {
                self.record_attempt_failure(transfer.id, "upload state is invalid", now_ms)?;
                return Err(error);
            }
        };
        if !(TransferRule {
            wifi_only: record.wifi_only,
        })
        .allows(network)
        {
            self.release(transfer.id, now_ms)?;
            return Ok(Some((transfer.id, Vec::new())));
        }

        // An upload whose completion was sent (or done) finishes from its
        // record alone: its staging may already be gone, and its source may
        // have changed since, but the server may have published it.
        if record.remote_completed || record.complete_name_encrypted.is_some() {
            if let Err(error) = self
                .finish_completed_upload(transfer.id, &mut record, None, now_ms)
                .await
            {
                self.completion_failed(transfer.id, &error, now_ms)?;
                return Err(error);
            }
            return Ok(Some((transfer.id, Vec::new())));
        }
        if record.restart_intent.is_some() {
            let _current_source = match source_identity(&record.source_path) {
                Ok(source) => source,
                Err(error) => {
                    self.record_attempt_failure(transfer.id, "upload source is unavailable", now_ms)?;
                    return Err(error);
                }
            };
            self.finish_restart_intent(transfer.id, &mut record, now_ms).await?;
            self.release(transfer.id, now_ms)?;
            self.emit(UploadEvent::SourceChanged { id: transfer.id });
            return Err(UploadServiceError::SourceChangedRestarted);
        }
        if record.planner.is_none() && record.session_id.is_some() {
            let current_source = match source_identity(&record.source_path) {
                Ok(source) => source,
                Err(error) => {
                    self.record_attempt_failure(transfer.id, "upload source is unavailable", now_ms)?;
                    return Err(error);
                }
            };
            let plan = BackgroundRestartPlan {
                file_id: record.file_id.clone(),
                upload_session_id: record.session_id.clone().ok_or(UploadServiceError::State)?,
                cleanup: SignOutPlan {
                    cancel_tickets: Vec::new(),
                    delete_files: staged_files(&self.upload_directory(transfer.id)),
                },
            };
            self.begin_restart(transfer.id, &mut record, &plan, current_source, now_ms)
                .await?;
            self.release(transfer.id, now_ms)?;
            return Err(UploadServiceError::SourceChangedRestarted);
        }
        let session_key = self.client.session_key()?;
        let mut planner = match record.planner.as_deref() {
            Some(bytes) => {
                let restored = match source_identity(&record.source_path) {
                    Ok(current_source) => {
                        BackgroundUploadPlanner::from_bytes(bytes, &self.upload_directory(transfer.id), &current_source)
                    }
                    Err(_) => {
                        BackgroundUploadPlanner::from_bytes_after_staging(bytes, &self.upload_directory(transfer.id))
                    }
                };
                let restored = match restored {
                    Ok(restored) => restored,
                    Err(error) => {
                        self.record_attempt_failure(transfer.id, "upload state is invalid", now_ms)?;
                        return Err(map_background(error));
                    }
                };
                match restored {
                    BackgroundRestore::Resumed(planner) => {
                        if !planner.all_chunks_staged()
                            && !planner
                                .staged_plaintext_matches(
                                    File::open(&record.source_path).map_err(|_| UploadServiceError::Source)?,
                                )
                                .map_err(map_background)?
                        {
                            let plan = planner.restart_plan();
                            let current_source = source_identity(&record.source_path)?;
                            self.begin_restart(transfer.id, &mut record, &plan, current_source, now_ms)
                                .await?;
                            self.release(transfer.id, now_ms)?;
                            self.emit(UploadEvent::SourceChanged { id: transfer.id });
                            return Err(UploadServiceError::SourceChangedRestarted);
                        }
                        planner
                    }
                    BackgroundRestore::AbandonAndRestart(plan) => {
                        let current_source = source_identity(&record.source_path)?;
                        self.begin_restart(transfer.id, &mut record, &plan, current_source, now_ms)
                            .await?;
                        self.release(transfer.id, now_ms)?;
                        self.emit(UploadEvent::SourceChanged { id: transfer.id });
                        return Err(UploadServiceError::SourceChangedRestarted);
                    }
                }
            }
            None => match self.initialize(transfer.id, &mut record, &session_key, now_ms).await {
                Ok(planner) => planner,
                Err(error) => {
                    if upload_upgrade_required(&error) {
                        self.mark_upgrade_required(transfer.id, now_ms)?;
                    } else if matches!(
                        error,
                        UploadServiceError::QuotaFull
                            | UploadServiceError::HostileChunkPlan
                            | UploadServiceError::Protected(_)
                    ) {
                        self.store
                            .lock()
                            .map_err(|_| UploadServiceError::State)?
                            .mark_transfer_failed(transfer.id, "upload cannot be started", now_ms)
                            .map_err(|_| UploadServiceError::State)?;
                    } else {
                        self.record_attempt_failure(transfer.id, "upload initialization failed", now_ms)?;
                    }
                    return Err(error);
                }
            },
        };

        let stage_result = self.stage_more(&record, &mut planner, &session_key);
        if stage_result.is_ok() && !planner.staged_plaintext_hash_complete() {
            let source = File::open(&record.source_path).map_err(|_| UploadServiceError::Source)?;
            if let Err(error) = planner.record_staged_plaintext_hash(source).map_err(map_background) {
                record.planner = Some(planner.to_bytes().map_err(map_background)?);
                self.persist(transfer.id, &record, now_ms)?;
                self.record_attempt_failure(transfer.id, "upload source hashing failed", now_ms)?;
                return Err(error);
            }
        }
        record.planner = Some(planner.to_bytes().map_err(map_background)?);
        self.persist(transfer.id, &record, now_ms)?;
        let stage_generation = match stage_result {
            Ok(generation) => generation,
            Err(error) => {
                self.record_attempt_failure(transfer.id, "upload staging failed", now_ms)?;
                return Err(error);
            }
        };
        if planner.all_chunks_staged() && planner.remaining_chunks() == 0 {
            if let Err(error) = self
                .finish_completed_upload(transfer.id, &mut record, Some(&planner), now_ms)
                .await
            {
                self.completion_failed(transfer.id, &error, now_ms)?;
                return Err(error);
            }
            return Ok(Some((transfer.id, Vec::new())));
        }
        let token = match self
            .client
            .execute_for_generation(
                &beebeeb_api::proposed::mint_upload_token(
                    record.session_id.as_deref().ok_or(UploadServiceError::State)?,
                ),
                &(),
                stage_generation,
            )
            .await
        {
            Ok(token) => token,
            Err(error) => {
                if client_upgrade_required(&error) {
                    self.mark_upgrade_required(transfer.id, now_ms)?;
                } else {
                    self.record_attempt_failure(transfer.id, "upload token mint failed", now_ms)?;
                }
                return Err(error.into());
            }
        };
        if token.upload_session_id != record.session_id.as_deref().ok_or(UploadServiceError::State)? {
            self.record_attempt_failure(transfer.id, "upload token did not match its session", now_ms)?;
            return Err(UploadServiceError::HostileChunkPlan);
        }
        let requests = planner.next_transfers(limit, &token.token, u64::try_from(now_ms).unwrap_or(0));
        record.planner = Some(planner.to_bytes().map_err(map_background)?);
        self.persist(transfer.id, &record, now_ms)?;
        if requests.is_empty() {
            self.release(transfer.id, now_ms)?;
            self.emit(UploadEvent::Changed {
                id: transfer.id,
                state: TransferState::Queued,
            });
        } else {
            self.emit(UploadEvent::Changed {
                id: transfer.id,
                state: TransferState::Running,
            });
        }
        Ok(Some((transfer.id, requests)))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn transfer_finished(
        &self,
        id: i64,
        ticket: &str,
        status: u16,
        content_type: Option<&str>,
        retry_after: Option<&str>,
        body: &[u8],
        now_ms: i64,
    ) -> Result<TransferFinished, UploadServiceError> {
        let transfer = self.transfer(id)?;
        let mut record = decode_record(&transfer.payload)?;
        let bytes = record.planner.as_deref().ok_or(UploadServiceError::State)?;
        let restored = match source_identity(&record.source_path) {
            Ok(current) => BackgroundUploadPlanner::from_bytes(bytes, &self.upload_directory(id), &current),
            Err(_) => BackgroundUploadPlanner::from_bytes_after_staging(bytes, &self.upload_directory(id)),
        }
        .map_err(map_background)?;
        let mut planner = match restored {
            BackgroundRestore::Resumed(planner) => planner,
            BackgroundRestore::AbandonAndRestart(plan) => {
                let current = source_identity(&record.source_path)?;
                self.begin_restart(id, &mut record, &plan, current, now_ms).await?;
                return Err(UploadServiceError::SourceChangedRestarted);
            }
        };
        let result = planner.transfer_finished(
            ticket,
            status,
            content_type,
            retry_after,
            body,
            u64::try_from(now_ms).unwrap_or(0),
        );
        if matches!(result, TransferFinished::UploadTokenExpired { .. }) {
            self.emit(UploadEvent::TokenExpired { id });
        }
        if matches!(result, TransferFinished::Failed { .. }) {
            self.store
                .lock()
                .map_err(|_| UploadServiceError::State)?
                .mark_transfer_failed(id, "upload failed", now_ms)
                .map_err(|_| UploadServiceError::State)?;
            self.emit(UploadEvent::Changed {
                id,
                state: TransferState::Failed,
            });
        } else if matches!(result, TransferFinished::Committed { .. })
            && planner.all_chunks_staged()
            && planner.remaining_chunks() == 0
        {
            record.planner = Some(planner.to_bytes().map_err(map_background)?);
            self.persist(id, &record, now_ms)?;
            if let Err(error) = self
                .finish_completed_upload(id, &mut record, Some(&planner), now_ms)
                .await
            {
                self.completion_failed(id, &error, now_ms)?;
                return Err(error);
            }
        } else {
            record.planner = Some(planner.to_bytes().map_err(map_background)?);
            self.persist(id, &record, now_ms)?;
            self.release(id, now_ms)?;
        }
        Ok(result)
    }

    pub fn pause(&self, id: i64, now_ms: i64) -> Result<bool, UploadServiceError> {
        let changed = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .pause_transfer(id, now_ms)
            .map_err(|_| UploadServiceError::State)?;
        if changed {
            self.emit(UploadEvent::Changed {
                id,
                state: TransferState::Paused,
            });
        }
        Ok(changed)
    }

    pub fn resume(&self, id: i64, now_ms: i64) -> Result<bool, UploadServiceError> {
        let changed = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .resume_transfer(id, now_ms)
            .map_err(|_| UploadServiceError::State)?;
        if changed {
            self.emit(UploadEvent::Changed {
                id,
                state: TransferState::Queued,
            });
        }
        Ok(changed)
    }

    pub fn cancel(&self, id: i64, now_ms: i64) -> Result<SignOutPlan, UploadServiceError> {
        let transfer = self.transfer(id)?;
        let record = decode_record(&transfer.payload)?;
        let mut plan = SignOutPlan {
            cancel_tickets: Vec::new(),
            delete_files: Vec::new(),
        };
        if let Some(bytes) = record.planner.as_deref() {
            let current = source_identity(&record.source_path).unwrap_or(record.source_identity.clone());
            plan = match BackgroundUploadPlanner::from_bytes(bytes, &self.upload_directory(id), &current)
                .map_err(map_background)?
            {
                BackgroundRestore::Resumed(mut planner) => planner.sign_out(),
                BackgroundRestore::AbandonAndRestart(restart) => restart.cleanup,
            };
        }
        self.store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .cancel_transfer(id, now_ms)
            .map_err(|_| UploadServiceError::State)?;
        self.emit(UploadEvent::Changed {
            id,
            state: TransferState::Cancelled,
        });
        Ok(plan)
    }

    /// Cancel every upload not yet done whose source file `owned` claims
    /// (an archive service's own staged files, left by an earlier process),
    /// and delete their staged chunks. How many were cancelled. Uploads of
    /// any other file, wherever it is, are left alone.
    pub fn cancel_sources_matching(
        &self,
        owned: &dyn Fn(&std::path::Path) -> bool,
        now_ms: i64,
    ) -> Result<usize, UploadServiceError> {
        let ids: Vec<i64> = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .transfers(Some(UPLOAD_KIND))
            .map_err(|_| UploadServiceError::State)?
            .into_iter()
            .filter(|transfer| !matches!(transfer.state, TransferState::Succeeded | TransferState::Cancelled))
            .filter(|transfer| decode_record(&transfer.payload).is_ok_and(|record| owned(&record.source_path)))
            .map(|transfer| transfer.id)
            .collect();
        let mut cancelled = 0;
        for id in ids {
            // One that cannot be cancelled now fails on its own: its source
            // is deleted next.
            if let Ok(plan) = self.cancel(id, now_ms) {
                cancelled += 1;
                for path in plan.delete_files {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        Ok(cancelled)
    }

    pub fn list(&self) -> Result<Vec<UploadSummary>, UploadServiceError> {
        self.store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .transfers(Some(UPLOAD_KIND))
            .map_err(|_| UploadServiceError::State)?
            .into_iter()
            .map(|transfer| {
                let record = decode_record(&transfer.payload)?;
                Ok(UploadSummary {
                    id: transfer.id,
                    file_id: record.file_id,
                    name: record.name,
                    state: transfer.state,
                    attempts: transfer.attempts,
                    last_error: transfer.last_error,
                })
            })
            .collect()
    }

    pub fn pending_backup_outcomes(&self) -> Result<Vec<BackupUploadOutcome>, UploadServiceError> {
        let outcomes = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .transfers(Some(UPLOAD_KIND))
            .map_err(|_| UploadServiceError::State)?
            .into_iter()
            .filter_map(|transfer| {
                let record = decode_record(&transfer.payload).ok()?;
                let local_identifier = record.backup_local_identifier?;
                if record.backup_outcome_applied {
                    return None;
                }
                let kind = match transfer.state {
                    TransferState::Succeeded if record.remote_completed => BackupUploadOutcomeKind::Completed,
                    TransferState::Failed => BackupUploadOutcomeKind::Failed,
                    TransferState::Cancelled => BackupUploadOutcomeKind::Cancelled,
                    _ => return None,
                };
                Some(BackupUploadOutcome {
                    upload_id: transfer.id,
                    local_identifier,
                    file_id: record.file_id,
                    kind,
                })
            })
            .collect();
        Ok(outcomes)
    }

    /// Cancel every backup upload that is not done, delete its staged
    /// chunks, and mark its outcome applied, so a stop is never counted as a
    /// failed upload (a stopped backup never fills the account up again, core
    /// Never break). The cancelled uploads' local identifiers. Every upload
    /// is tried; one that fails does not stop the others, and the first error
    /// is returned once all were tried.
    pub fn cancel_backup_uploads(&self, now_ms: i64) -> Result<Vec<String>, UploadServiceError> {
        let active: Vec<(i64, String)> = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .transfers(Some(UPLOAD_KIND))
            .map_err(|_| UploadServiceError::State)?
            .into_iter()
            .filter(|transfer| {
                matches!(
                    transfer.state,
                    TransferState::Queued | TransferState::Running | TransferState::Paused
                )
            })
            .filter_map(|transfer| {
                let record = decode_record(&transfer.payload).ok()?;
                Some((transfer.id, record.backup_local_identifier?))
            })
            .collect();
        let mut cancelled = Vec::with_capacity(active.len());
        let mut first_error = None;
        for (id, local_identifier) in active {
            match self.cancel_backup_upload(id, now_ms) {
                Ok(()) => cancelled.push(local_identifier),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(cancelled), Err)
    }

    fn cancel_backup_upload(&self, id: i64, now_ms: i64) -> Result<(), UploadServiceError> {
        match self.cancel(id, now_ms) {
            Ok(plan) => remove_planned_files(&plan),
            // Its planner could not be read: it is cancelled all the same,
            // so it never completes; its staged chunks stay until sign-out.
            Err(_) => {
                self.store
                    .lock()
                    .map_err(|_| UploadServiceError::State)?
                    .cancel_transfer(id, now_ms)
                    .map_err(|_| UploadServiceError::State)?;
                self.emit(UploadEvent::Changed {
                    id,
                    state: TransferState::Cancelled,
                });
            }
        }
        self.mark_backup_outcome_applied(id, now_ms)
    }

    pub fn active_backup_count(&self) -> Result<usize, UploadServiceError> {
        let count = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .transfers(Some(UPLOAD_KIND))
            .map_err(|_| UploadServiceError::State)?
            .into_iter()
            .filter(|transfer| {
                matches!(
                    transfer.state,
                    TransferState::Queued | TransferState::Running | TransferState::Paused
                ) && decode_record(&transfer.payload)
                    .ok()
                    .is_some_and(|record| record.backup_local_identifier.is_some())
            })
            .count();
        Ok(count)
    }

    pub fn mark_backup_outcome_applied(&self, id: i64, now_ms: i64) -> Result<(), UploadServiceError> {
        let transfer = self.transfer(id)?;
        let mut record = decode_record(&transfer.payload)?;
        if record.backup_local_identifier.is_none() {
            return Err(UploadServiceError::State);
        }
        record.backup_outcome_applied = true;
        let payload = encode_record(&record)?;
        if !self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .update_final_transfer_payload(id, &payload, now_ms)
            .map_err(|_| UploadServiceError::State)?
        {
            return Err(UploadServiceError::NotActive);
        }
        Ok(())
    }

    /// Stop and discard every account-bound upload before store deletion.
    pub fn sign_out(&self, now_ms: i64) -> Result<SignOutPlan, UploadServiceError> {
        let ids: Vec<i64> = self.list()?.into_iter().map(|item| item.id).collect();
        let mut combined = SignOutPlan {
            cancel_tickets: Vec::new(),
            delete_files: Vec::new(),
        };
        for id in ids {
            if let Ok(plan) = self.cancel(id, now_ms) {
                combined.cancel_tickets.extend(plan.cancel_tickets);
                combined.delete_files.extend(plan.delete_files);
            }
        }
        Ok(combined)
    }

    /// Delete staged ciphertext after the platform has consumed the returned
    /// cancellation tickets. Repeating this is harmless.
    pub fn finalize_sign_out(&self, plan: &SignOutPlan) {
        remove_planned_files(plan);
    }
}
