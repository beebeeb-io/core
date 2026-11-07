    use super::*;
    use beebeeb_core::chunk_stream::{ChunkDecryptor, ExpectedChunkFormat};
    use beebeeb_core::kdf::FileKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "beebeeb-transfer-background-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn grant(index: u32) -> BackgroundGrant {
        BackgroundGrant {
            index,
            url: format!("https://api.test/chunks/{index}"),
            headers: vec![("content-type".into(), "application/octet-stream".into())],
            commit_path: None,
            requires_upload_token: true,
        }
    }

    fn source(size: u64) -> UploadSourceIdentity {
        UploadSourceIdentity {
            size_bytes: size,
            modified_unix_ms: 1_700_000_000_123,
            content_hash: Some([0x51; 32]),
        }
    }

    #[test]
    fn state_survives_a_kill_and_duplicate_or_unknown_tickets_are_harmless() {
        let scratch = Scratch::new();
        let plain = b"plaintext must never be staged";
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([9; 32]),
            "11111111-2222-4333-8444-555555555555",
            plain.len() as u64,
            8,
            std::io::Cursor::new(plain.to_vec()),
        )
        .unwrap();
        let count = encryptor.chunk_plan().chunk_count as u32;
        let identity = source(plain.len() as u64);
        let mut planner = BackgroundUploadPlanner::new(
            "u",
            "s",
            "11111111-2222-4333-8444-555555555555",
            &scratch.0,
            4096,
            8,
            count,
            identity.clone(),
        )
        .unwrap();
        let grants: Vec<_> = (0..count).map(grant).collect();
        let progress = planner.stage_available(&mut encryptor, &grants, None).unwrap();
        assert!(progress.all_chunks_staged);
        planner
            .record_staged_plaintext_hash(std::io::Cursor::new(plain.to_vec()))
            .unwrap();
        planner.finish_encryption(encryptor).unwrap();
        let first_path = planner.state.directory.join(&planner.state.chunks[0].file_name);
        assert_ne!(fs::read(&first_path).unwrap(), plain);

        let bytes = planner.to_bytes().unwrap();
        let BackgroundRestore::Resumed(mut restored) =
            BackgroundUploadPlanner::from_bytes(&bytes, &scratch.0, &identity).unwrap()
        else {
            panic!("unchanged source must resume");
        };
        let request = restored.next_transfers(1, "scoped", 0).remove(0);
        assert!(request.headers.iter().any(|(_, value)| value == "Bearer scoped"));
        assert_eq!(
            restored.transfer_finished("unknown", 200, None, None, b"", 0),
            TransferFinished::Ignored
        );
        assert!(matches!(
            restored.transfer_finished(&request.ticket, 200, None, None, b"", 0),
            TransferFinished::Committed { index: 0 }
        ));
        assert_eq!(
            restored.transfer_finished(&request.ticket, 200, None, None, b"", 0),
            TransferFinished::Ignored
        );
        assert!(!request.body_path.exists());
    }

    #[test]
    fn expired_scoped_token_keeps_ciphertext_ready_for_a_fresh_token() {
        let scratch = Scratch::new();
        let plain = b"one chunk";
        let identity = source(plain.len() as u64);
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([8; 32]),
            "11111111-2222-4333-8444-555555555555",
            plain.len() as u64,
            32,
            std::io::Cursor::new(plain.to_vec()),
        )
        .unwrap();
        let mut planner = BackgroundUploadPlanner::new(
            "u",
            "s",
            "11111111-2222-4333-8444-555555555555",
            &scratch.0,
            4096,
            32,
            1,
            identity,
        )
        .unwrap();
        planner.stage_available(&mut encryptor, &[grant(0)], None).unwrap();
        planner.finish_encryption(encryptor).unwrap();
        let first = planner.next_transfers(1, "expired", 0).remove(0);
        assert_eq!(
            planner.transfer_finished(&first.ticket, 401, None, None, b"", 0),
            TransferFinished::UploadTokenExpired { index: 0 }
        );
        assert!(first.body_path.exists());
        let second = planner.next_transfers(1, "fresh", 1).remove(0);
        assert!(second.headers.iter().any(|(_, value)| value == "Bearer fresh"));
    }

    #[test]
    fn upgrade_required_chunk_answer_is_terminal_without_a_retry() {
        let scratch = Scratch::new();
        let plain = b"one chunk";
        let identity = source(plain.len() as u64);
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([8; 32]),
            "11111111-2222-4333-8444-555555555555",
            plain.len() as u64,
            32,
            std::io::Cursor::new(plain.to_vec()),
        )
        .unwrap();
        let mut planner = BackgroundUploadPlanner::new(
            "u",
            "s",
            "11111111-2222-4333-8444-555555555555",
            &scratch.0,
            4096,
            32,
            1,
            identity,
        )
        .unwrap();
        planner.stage_available(&mut encryptor, &[grant(0)], None).unwrap();
        planner.finish_encryption(encryptor).unwrap();
        let request = planner.next_transfers(1, "scoped", 0).remove(0);

        let result = planner.transfer_finished(
            &request.ticket,
            426,
            Some("application/json"),
            None,
            br#"{"error":"client_upgrade_required","secret":"must-not-escape"}"#,
            0,
        );
        assert_eq!(
            result,
            TransferFinished::Failed {
                index: 0,
                reason: BackgroundFailure::UpgradeRequired,
            }
        );
        assert!(planner.next_transfers(1, "scoped", 1).is_empty());
    }

    #[test]
    fn upgrade_required_direct_commit_is_terminal_without_a_retry() {
        let scratch = Scratch::new();
        let plain = b"one chunk";
        let identity = source(plain.len() as u64);
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([8; 32]),
            "11111111-2222-4333-8444-555555555555",
            plain.len() as u64,
            32,
            std::io::Cursor::new(plain.to_vec()),
        )
        .unwrap();
        let mut planner = BackgroundUploadPlanner::new(
            "u",
            "s",
            "11111111-2222-4333-8444-555555555555",
            &scratch.0,
            4096,
            32,
            1,
            identity,
        )
        .unwrap();
        let mut direct = grant(0);
        direct.commit_path = Some("/api/v1/uploads/s/chunks/0/commit".into());
        planner.stage_available(&mut encryptor, &[direct], None).unwrap();
        planner.finish_encryption(encryptor).unwrap();
        let request = planner.next_transfers(1, "scoped", 0).remove(0);
        assert!(matches!(
            planner.transfer_finished(&request.ticket, 200, None, None, b"", 0),
            TransferFinished::CommitRequired(_)
        ));

        let result = planner.transfer_finished(
            &request.ticket,
            426,
            Some("application/json"),
            None,
            br#"{"error":"client_upgrade_required","secret":"must-not-escape"}"#,
            0,
        );
        assert_eq!(
            result,
            TransferFinished::Failed {
                index: 0,
                reason: BackgroundFailure::UpgradeRequired,
            }
        );
        assert!(planner.next_transfers(1, "scoped", 1).is_empty());
    }

    #[test]
    fn disk_limit_stops_before_consuming_the_next_plaintext_chunk() {
        let scratch = Scratch::new();
        let plain = vec![7u8; 32];
        let identity = source(plain.len() as u64);
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([3; 32]),
            "11111111-2222-4333-8444-555555555555",
            plain.len() as u64,
            16,
            std::io::Cursor::new(plain),
        )
        .unwrap();
        let mut planner = BackgroundUploadPlanner::new(
            "u",
            "s",
            "11111111-2222-4333-8444-555555555555",
            &scratch.0,
            44,
            16,
            2,
            identity,
        )
        .unwrap();
        let progress = planner
            .stage_available(&mut encryptor, &[grant(0), grant(1)], None)
            .unwrap();
        assert_eq!(progress.staged, 1);
        assert!(progress.disk_limit_reached);
        assert_eq!(encryptor.chunks_emitted(), 1);
    }

    #[test]
    fn process_kill_resumes_unstaged_v2_chunks_with_the_same_commitment() {
        const ID: &str = "22222222-2222-4222-8222-222222222222";
        let scratch = Scratch::new();
        let plain: Vec<u8> = (0..73).map(|index| (index % 251) as u8).collect();
        let key = [0x29; 32];
        let identity = source(plain.len() as u64);
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes(key),
            ID,
            plain.len() as u64,
            16,
            std::io::Cursor::new(plain.clone()),
        )
        .unwrap();
        let count = encryptor.chunk_plan().chunk_count as u32;
        let mut planner =
            BackgroundUploadPlanner::new("upload", "session", ID, &scratch.0, 4096, 16, count, identity.clone())
                .unwrap();
        planner.stage_available(&mut encryptor, &[grant(0)], Some(7)).unwrap();
        planner
            .record_staged_plaintext_hash(std::io::Cursor::new(plain.clone()))
            .unwrap();
        let commitment = planner.version_commitment().unwrap();
        let mut frames = vec![fs::read(planner.state.directory.join(&planner.state.chunks[0].file_name)).unwrap()];
        let persisted = planner.to_bytes().unwrap();
        assert!(!persisted.windows(key.len()).any(|window| window == key));
        drop(encryptor);

        let BackgroundRestore::Resumed(mut restored) =
            BackgroundUploadPlanner::from_bytes(&persisted, &scratch.0, &identity).unwrap()
        else {
            panic!("unchanged source must resume");
        };
        assert_eq!(restored.version_commitment(), Some(commitment));
        let mut resumed = restored
            .resume_encryptor_with_file_key(FileKey::from_bytes(key), std::io::Cursor::new(plain.clone()))
            .unwrap();
        let grants: Vec<_> = (1..count).map(grant).collect();
        let progress = restored.stage_available(&mut resumed, &grants, Some(7)).unwrap();
        assert!(progress.all_chunks_staged);
        restored.finish_encryption(resumed).unwrap();
        for chunk in restored.state.chunks.iter().skip(1) {
            frames.push(fs::read(restored.state.directory.join(&chunk.file_name)).unwrap());
        }

        let mut decryptor = ChunkDecryptor::for_version_with_file_key(
            FileKey::from_bytes(key),
            ID,
            ExpectedChunkFormat::V2,
            Some(commitment),
        );
        let mut recovered = Vec::new();
        for frame in frames {
            recovered.extend_from_slice(&decryptor.push_frame(&frame).unwrap().data);
        }
        decryptor.finish().unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn changed_source_requires_abandon_and_restart() {
        const ID: &str = "33333333-3333-4333-8333-333333333333";
        let scratch = Scratch::new();
        let plain = vec![0x44; 40];
        let identity = source(plain.len() as u64);
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([4; 32]),
            ID,
            plain.len() as u64,
            16,
            std::io::Cursor::new(plain),
        )
        .unwrap();
        let mut planner =
            BackgroundUploadPlanner::new("upload", "session", ID, &scratch.0, 4096, 16, 3, identity.clone()).unwrap();
        planner.stage_available(&mut encryptor, &[grant(0)], None).unwrap();
        let bytes = planner.to_bytes().unwrap();
        let mut changed = identity;
        changed.modified_unix_ms += 1;

        let BackgroundRestore::AbandonAndRestart(restart) =
            BackgroundUploadPlanner::from_bytes(&bytes, &scratch.0, &changed).unwrap()
        else {
            panic!("changed source must not resume");
        };
        assert_eq!(restart.file_id, ID);
        assert_eq!(restart.upload_session_id, "session");
        assert_eq!(restart.cleanup.delete_files.len(), 1);
    }

    #[test]
    fn same_size_same_mtime_changed_prefix_requires_restart() {
        const ID: &str = "44444444-4444-4444-8444-444444444444";
        let scratch = Scratch::new();
        let identity = source(32);
        let original = vec![0x11; 32];
        let mut encryptor = ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([5; 32]),
            ID,
            32,
            16,
            std::io::Cursor::new(original.clone()),
        )
        .unwrap();
        let mut planner =
            BackgroundUploadPlanner::new("upload", "session", ID, &scratch.0, 4096, 16, 2, identity.clone()).unwrap();
        planner.stage_available(&mut encryptor, &[grant(0)], None).unwrap();
        planner
            .record_staged_plaintext_hash(std::io::Cursor::new(original))
            .unwrap();
        let bytes = planner.to_bytes().unwrap();

        let changed = vec![0x22; 32];
        let BackgroundRestore::Resumed(restored) =
            BackgroundUploadPlanner::from_bytes(&bytes, &scratch.0, &identity).unwrap()
        else {
            panic!("weak source identity should still reach prefix verification");
        };
        assert!(
            !restored
                .staged_plaintext_matches(std::io::Cursor::new(changed))
                .unwrap()
        );
    }

    #[test]
    fn restore_removes_an_unreferenced_ciphertext_file_before_restaging_it() {
        let scratch = Scratch::new();
        let identity = source(10);
        let planner = BackgroundUploadPlanner::new(
            "upload",
            "session",
            "11111111-2222-4333-8444-555555555555",
            &scratch.0,
            4096,
            32,
            1,
            identity.clone(),
        )
        .unwrap();
        let orphan = scratch.0.join("chunk-00000000.bbcipher");
        fs::write(&orphan, b"orphan").unwrap();

        let BackgroundRestore::Resumed(_) =
            BackgroundUploadPlanner::from_bytes(&planner.to_bytes().unwrap(), &scratch.0, &identity).unwrap()
        else {
            panic!("unchanged source should resume");
        };
        assert!(!orphan.exists());
    }
