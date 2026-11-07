use super::*;

impl UploadService {
    pub(super) async fn initialize(
        &self,
        id: i64,
        record: &mut UploadRecord,
        session_key: &crate::SessionKey,
        now_ms: i64,
    ) -> Result<BackgroundUploadPlanner, UploadServiceError> {
        let preliminary_name = if let Some(replacement) = &record.replacement {
            replacement.current_version_metadata_encrypted.clone()
        } else {
            let item = NewItemId::resume(session_key.master_key(), &record.file_id, &record.item_tag)
                .map_err(|_| UploadServiceError::Encryption)?;
            encrypt_name_for_new_item(
                session_key.master_key(),
                &item,
                &record.name,
                record.mime_type.as_deref(),
                ExpectedChunkFormat::V2,
            )
            .map_err(|_| UploadServiceError::Encryption)?
        };
        let request = InitRequest {
            file_id: Some(record.file_id.clone()),
            file_name: preliminary_name,
            file_size_bytes: record.source_identity.size_bytes,
            parent_id: record.parent_id.clone(),
            profile: beebeeb_types::ChunkProfile::Mobile,
            preferred_region: None,
            chunk_size_bytes: None,
            chunk_count: None,
            is_media: record
                .mime_type
                .as_deref()
                .is_some_and(|value| value.starts_with("image/") || value.starts_with("video/")),
            base_version_number: record
                .replacement
                .as_ref()
                .map(|replacement| replacement.base_version_number),
            created_at: None,
            conflict_created: false,
            version_metadata_encrypted: record
                .replacement
                .as_ref()
                .map(|replacement| replacement.current_version_metadata_encrypted.clone()),
        };
        let response = match self
            .client
            .execute_for_generation(
                &beebeeb_api::routes::uploads::init(),
                &request,
                session_key.generation(),
            )
            .await
        {
            Ok(response) => response,
            Err(ClientError::Api(beebeeb_api::ApiError::Server(error)))
                if error.is_code("quota_exceeded") || error.is_trial_cap() || error.status == 507 =>
            {
                self.emit(UploadEvent::QuotaFull { id });
                return Err(UploadServiceError::QuotaFull);
            }
            Err(error) => return Err(error.into()),
        };
        if !session_key.is_current(&self.client) {
            return Err(ClientError::StaleAccount.into());
        }
        let chunk_count = validate_geometry(
            record.source_identity.size_bytes,
            response.chunk_size_bytes,
            response.chunk_count,
        )?;
        if response.file_id != record.file_id || response.upload_session_id.is_empty() {
            return Err(UploadServiceError::HostileChunkPlan);
        }
        let directory = self.upload_directory(id);
        std::fs::create_dir_all(&directory).map_err(|_| UploadServiceError::State)?;
        let planner = BackgroundUploadPlanner::new(
            id.to_string(),
            response.upload_session_id.clone(),
            record.file_id.clone(),
            directory,
            record.disk_limit,
            response.chunk_size_bytes,
            chunk_count,
            record.source_identity.clone(),
        )
        .map_err(map_background)?;
        record.session_id = Some(response.upload_session_id);
        record.chunk_size = Some(response.chunk_size_bytes);
        record.chunk_count = Some(chunk_count);
        self.persist(id, record, now_ms)?;
        Ok(planner)
    }

    pub(super) fn stage_more(
        &self,
        record: &UploadRecord,
        planner: &mut BackgroundUploadPlanner,
        session_key: &crate::SessionKey,
    ) -> Result<u64, UploadServiceError> {
        if planner.all_chunks_staged() {
            return Ok(session_key.generation());
        }
        let file = File::open(&record.source_path).map_err(|_| UploadServiceError::Source)?;
        let chunk_size = record.chunk_size.ok_or(UploadServiceError::State)?;
        let chunk_count = record.chunk_count.ok_or(UploadServiceError::State)?;
        let mut encryptor = if planner.version_commitment().is_some() {
            planner
                .resume_encryptor(session_key.master_key(), file)
                .map_err(map_background)?
        } else {
            ChunkEncryptor::from_reader_with_chunk_size(
                session_key.master_key(),
                &record.file_id,
                record.source_identity.size_bytes,
                chunk_size,
                file,
            )
            .map_err(|_| UploadServiceError::Encryption)?
        };
        let start = encryptor.chunks_emitted();
        let session = record.session_id.as_deref().ok_or(UploadServiceError::State)?;
        let grants: Vec<_> = (start..chunk_count)
            .map(|index| BackgroundGrant {
                index,
                url: format!("/api/v1/uploads/{session}/chunks/{index}"),
                headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                commit_path: None,
                requires_upload_token: true,
            })
            .collect();
        let progress = planner
            .stage_available(
                &mut encryptor,
                &grants,
                record
                    .replacement
                    .as_ref()
                    .and_then(|replacement| replacement.previous_version_counter),
            )
            .map_err(map_background)?;
        if progress.staged == 0 && !progress.all_chunks_staged && planner.remaining_chunks() == 0 {
            return Err(UploadServiceError::State);
        }
        if progress.all_chunks_staged {
            planner.finish_encryption(encryptor).map_err(map_background)?;
        }
        if !session_key.is_current(&self.client) {
            return Err(ClientError::StaleAccount.into());
        }
        Ok(session_key.generation())
    }

    async fn complete(
        &self,
        id: i64,
        record: &UploadRecord,
        planner: &BackgroundUploadPlanner,
    ) -> Result<(), UploadServiceError> {
        let session_key = self.client.session_key()?;
        let version = planner.version_commitment().ok_or(UploadServiceError::Encryption)?;
        let name_encrypted = if record.replacement.is_some() {
            #[allow(deprecated)]
            beebeeb_core::encrypt::encrypt_name_with_version(
                session_key.master_key(),
                &record.file_id,
                &record.name,
                record.mime_type.as_deref(),
                ExpectedChunkFormat::V2,
                version,
            )
            .map_err(|_| UploadServiceError::Encryption)?
        } else {
            let item = NewItemId::resume(session_key.master_key(), &record.file_id, &record.item_tag)
                .map_err(|_| UploadServiceError::Encryption)?;
            encrypt_name_for_new_item_version(
                session_key.master_key(),
                &item,
                &record.name,
                record.mime_type.as_deref(),
                ExpectedChunkFormat::V2,
                version,
            )
            .map_err(|_| UploadServiceError::Encryption)?
        };
        let request = CompleteRequest {
            name_encrypted: Some(name_encrypted.clone()),
            version_metadata_encrypted: Some(name_encrypted),
        };
        self.client
            .execute_for_generation(
                &beebeeb_api::routes::uploads::complete(record.session_id.as_deref().ok_or(UploadServiceError::State)?),
                &request,
                session_key.generation(),
            )
            .await?;
        if !session_key.is_current(&self.client) {
            return Err(ClientError::StaleAccount.into());
        }
        let _ = std::fs::remove_dir(self.upload_directory(id));
        Ok(())
    }

    pub(super) async fn finish_completed_upload(
        &self,
        id: i64,
        record: &mut UploadRecord,
        planner: &BackgroundUploadPlanner,
        now_ms: i64,
    ) -> Result<(), UploadServiceError> {
        let generation = self.client.generation();
        if !record.remote_completed {
            self.complete(id, record, planner).await?;
            record.remote_completed = true;
            self.persist(id, record, now_ms)?;
        }
        if generation != self.client.generation() {
            return Err(ClientError::StaleAccount.into());
        }
        if let Some(local_identifier) = record.backup_local_identifier.as_deref() {
            let handler = self
                .completion_handler
                .lock()
                .map_err(|_| UploadServiceError::State)?
                .clone();
            if let Some(handler) = handler {
                handler
                    .completed(local_identifier, &record.file_id)
                    .await
                    .map_err(|_| UploadServiceError::State)?;
                if generation != self.client.generation() {
                    return Err(ClientError::StaleAccount.into());
                }
                record.backup_outcome_applied = true;
                self.persist(id, record, now_ms)?;
            }
        }
        self.mark_succeeded(id, now_ms)
    }

    pub(super) async fn begin_restart(
        &self,
        id: i64,
        record: &mut UploadRecord,
        plan: &BackgroundRestartPlan,
        source_identity: UploadSourceIdentity,
        now_ms: i64,
    ) -> Result<(), UploadServiceError> {
        record.restart_intent = Some(RestartIntent {
            source_identity,
            file_id: plan.file_id.clone(),
            upload_session_id: plan.upload_session_id.clone(),
            delete_files: plan.cleanup.delete_files.clone(),
        });
        self.persist(id, record, now_ms)?;
        self.finish_restart_intent(id, record, now_ms).await
    }

    pub(super) async fn finish_restart_intent(
        &self,
        id: i64,
        record: &mut UploadRecord,
        now_ms: i64,
    ) -> Result<(), UploadServiceError> {
        let intent = record.restart_intent.clone().ok_or(UploadServiceError::State)?;
        if let Err(error) = self
            .client
            .execute(&beebeeb_api::routes::uploads::abandon(&intent.file_id), &())
            .await
            .map(|_: beebeeb_api::routes::uploads::AbandonResponse| ())
        {
            if client_upgrade_required(&error) {
                self.mark_upgrade_required(id, now_ms)?;
            } else {
                self.record_attempt_failure(id, "upload restart abandon failed", now_ms)?;
            }
            return Err(error.into());
        }
        for path in &intent.delete_files {
            let _ = std::fs::remove_file(path);
        }
        record.source_identity = intent.source_identity;
        record.session_id = None;
        record.chunk_size = None;
        record.chunk_count = None;
        record.planner = None;
        record.restart_intent = None;
        self.persist(id, record, now_ms)
    }

    pub(super) fn upload_directory(&self, id: i64) -> PathBuf {
        self.staging_root.join(format!("upload-{id}"))
    }

    pub(super) fn transfer(&self, id: i64) -> Result<beebeeb_store::Transfer, UploadServiceError> {
        self.store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .transfer(id)
            .map_err(|_| UploadServiceError::State)?
            .ok_or(UploadServiceError::NotActive)
    }

    pub(super) fn persist(&self, id: i64, record: &UploadRecord, now_ms: i64) -> Result<(), UploadServiceError> {
        let payload = encode_record(record)?;
        if !self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .update_transfer_payload(id, &payload, now_ms)
            .map_err(|_| UploadServiceError::State)?
        {
            return Err(UploadServiceError::NotActive);
        }
        Ok(())
    }

    pub(super) fn release(&self, id: i64, now_ms: i64) -> Result<(), UploadServiceError> {
        self.store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .release_transfer(id, now_ms)
            .map_err(|_| UploadServiceError::State)?;
        Ok(())
    }

    pub(super) fn record_attempt_failure(&self, id: i64, message: &str, now_ms: i64) -> Result<(), UploadServiceError> {
        let transfer = self
            .store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .record_transfer_failure(id, message, now_ms)
            .map_err(|_| UploadServiceError::State)?;
        self.emit(UploadEvent::Changed {
            id,
            state: transfer.state,
        });
        Ok(())
    }

    pub(super) fn mark_upgrade_required(&self, id: i64, now_ms: i64) -> Result<(), UploadServiceError> {
        self.store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .mark_transfer_failed(id, "client upgrade required (HTTP 426)", now_ms)
            .map_err(|_| UploadServiceError::State)?;
        self.emit(UploadEvent::Changed {
            id,
            state: TransferState::Failed,
        });
        Ok(())
    }

    fn mark_succeeded(&self, id: i64, now_ms: i64) -> Result<(), UploadServiceError> {
        self.store
            .lock()
            .map_err(|_| UploadServiceError::State)?
            .mark_transfer_succeeded(id, now_ms)
            .map_err(|_| UploadServiceError::State)?;
        self.emit(UploadEvent::Changed {
            id,
            state: TransferState::Succeeded,
        });
        Ok(())
    }

    pub(super) fn emit(&self, event: UploadEvent) {
        let _ = self.events.send(event);
    }
}
