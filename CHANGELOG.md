# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - Unreleased

This is a breaking pre-1.0 release. The changes below are grouped by the people who must act.

### Native application maintainers

- Regenerate Swift and Kotlin bindings and update exhaustive switches. The default UniFFI surface now
  starts at `NativeClientHandle` and its opaque service handles. Raw-key functions and constructors,
  raw OPAQUE/recovery helpers, `upload_encrypted_file`, and `download_and_decrypt_file` are available
  only through the default-off `legacy-bindings` feature. Existing apps may enable it temporarily;
  new apps must not. Native WebP users must select `beebeeb-uniffi/webp-encode` explicitly.
- Supply a stable app id to `ClientConfig::new`. Session tokens are stored per app as
  `session.token.{app_id}` while the owner, master key, API URL, generation, and device identity are
  shared. App sign-out removes one token; whole-device sign-out removes all app tokens and shared
  state through `ServiceCoordinator`.
- Whole-device sign-out (`ServiceCoordinator::sign_out_device`, `sign_out_whole_device`) now removes
  the device on the server before account work stops, then sends a logout. A 401 on that logout
  counts as done. `SignOutFailure::Session` now means a real server or local failure.
- Native device registration sends the hardware identity as `client_key`, so two devices on one
  platform get separate device entries. Apps on one device share one entry.
- Recovery readiness comes from the server, never the device clock. `RecoveryAttempt::waits()` is
  true only while the server reports `pending`; call `recovery_status` to see the wait end. This
  needs a server that reports `ready`: against an older server a no-wait attempt stays waiting.
- Adopt the locked sign-in order: password, then the configured authenticator, yields a locked
  session. Complete one of device approval, passkey plus email code, or recovery key plus email code,
  then finish account-key proof. Email tickets are submitted at proof finish, not during password
  login. Signup is web-only. Account replacement requires an explicit replacement method and a
  confirmed last-device warning.
- Add the configured Keychain access-group entitlement to every iOS app and extension sharing a
  session. Secrets use a non-synchronizing, this-device-only, after-first-unlock Keychain item.
- Update transfer integration: factories no longer accept caller-supplied master keys, clocks, or
  Wi-Fi/staging policy. Load the session into `NativeClientHandle`, persist the new upload-staging
  setting, and pass `NetworkSignal`. `UploadError` and download failures add a context-handoff case;
  hand work to the main app with a fresh sink.
- Update backup, contacts, sync, and File Provider wrappers. Asset snapshots are paged; Rust records
  backup completion; contact services fetch keys themselves; the coordinator takes the shared store;
  sync exposes snapshot refresh and gap recovery; File Provider records can mark undecryptable names.
- Local store schema 3 adds paused/cancelled transfers, and schema 4 keys cache entries by authenticated
  file/version identity. Do not roll a database opened by this release back to an older binary. Old
  staged-upload state restarts because planner state 3 includes a staged-prefix commitment.

- `BackupConfigurationData` no longer has `managed_by`. Pass this device's folder under the Backups
  root (a device or category folder); the backup service checks its place below the row whose
  `system_role` is `backups_root` before it queues anything and refuses any other folder
  (`invalid_input`). `ServiceError::Protected { detail }` (kind `protected`) carries core's words when
  a change under Backups is refused; show them as they are. The field is `detail`, never `message`,
  which would collide with Kotlin's `Exception.message`.

- `RecoveryStateData` adds `Expired`: the server reports an attempt whose window to complete has passed
  as `expired`, and the status call returns that state instead of failing. Offer to start a new
  recovery.

- The native backup passes core's pass gate before it queues anything (backup spec Amendments 12 and
  12c). Each pass reads the `files_removed` and `backup_deleted` notices since its last pass (the
  server's filtered `GET /api/v1/notifications`, LD-0141) and whether its device and category folders
  are live. `BackupBatchData.stopped_reason` (a core wire string: show `backup_stop_words`, offer "Back
  up again") means the backup is off and its unfinished uploads were cancelled; `check_failed` means
  the notices could not be read and nothing was queued (show `backup_check_failed_words`). A stopped
  backup stays off until `BackupServiceHandle.back_up_again()`. `BackupManifestStoreCallback` adds
  `load_pass_state` and `save_pass_state` (`BackupPassStateData`, removed by `clear`), and
  `BackupConfigurationData` adds `setup_at_ms` and `legacy_last_backup_ms` (server clock) for the first
  pass's baseline. `BackupCopyStateData::Gone` is split into `Deleted` (removed on the server, never
  uploaded again by the pass) and `UploadFailed` (retried at most three times).
- Device link (UniFFI): `approve_device_link(id, scanned_qr, typed_code)` takes the raw text the camera
  scanned; `DeviceLinkQrData` and `DeviceLinkHandle.qr()` are removed (render `qr_payload()`). The QR
  now carries the device name: show `scanned_device_link_name(scanned_qr)` while the person confirms,
  never the pending link's `device_name`. A relay name that differs from the scanned one is
  `ServiceError::Authentication`, and the link is denied (Guus's ruling of 2026-11-07).
- Content readers (UniFFI): `FileKeyHandle.decrypt_chunk_frame(file_id, metadata, index, is_last,
  frame)` and `MasterKeyHandle.decrypt_file(file_id, metadata, …)` take the `NameMetadataDto` instead of
  a format code (and a version id). A `chunk_format: 2` record without a version commitment is refused;
  one with neither field opens v1 content only (Guus's ruling of 2026-11-07, "refuse v2 without
  commitment"). The
  typed-code path now starts at the approver: `begin_typed_device_approval` → relay its message → the
  new device's `answer_typed_path(approver_message)` → relay its answer →
  `approve_typed_device_link`, which checks the new device's confirmation before it seals and returns
  `ServiceError::Authentication` (and denies the link) for a wrong code or a changed device name.
  `TypedDeviceLinkHandle`, `TypedDeviceLinkStartData` and `begin_typed_path` are removed;
  `TypedDeviceApprovalStartData` adds `device_name`. Show that name while the person types the code.
- Content decryptors (UniFFI) take the decrypted metadata: `ChunkDecryptorHandle.from_file`,
  `for_push`, `for_push_with_file_key_handle` and the legacy `for_push_with_file_key` take a
  `NameMetadataDto` in place of `expected_chunk_format`, and enforce its version commitment. Key-handle
  holders reading a historical version use the new `for_version_with_file_key_handle`.
- `RecoveryChangesData`'s codes and password and `PasskeyPromptResult.prf_output` are `SecretString` /
  `SecretBytes`: the same `String` and `Data` / `ByteArray` in Swift and Kotlin, wiped and redacted in
  Rust. New: `safety_number` and `normalize_email`.

- Archives: `list_archive`, `decompress_gzip`, `list_tar_entries` and `ArchiveEntryDto` are removed
  (the extension-based `beebeeb_core::archive` is deleted). List, preview and extract archives through
  `NativeClientHandle.archives(...)` → `ArchiveServiceHandle`: `open`, `preview`, `extract`,
  `supply_password`, `open_entry`, `cancel`, `close`, `observe`. Show core's preview model and words as
  they are; drive uploads as for any upload (the service enqueues each verified file); keep the app open
  while it reads (`extract_keep_open`).

### Rust sync and conflict integrators

- Replace `SyncEngine::load_snapshot` with `apply_complete_snapshot(CompleteSnapshot)` only for an
  explicitly complete, cursor-bound answer. Use `observe_incomplete_snapshot` for partial listings;
  it never deletes.
- `apply_remote_op` now takes `RemoteOp` and returns `Result<Option<SyncEvent>, SyncEngineError>`.
  `SyncOp` adds `user_seq`; persist `SyncPosition { seq_id, user_seq }`, and fetch a complete snapshot
  after `SequenceGap`. Engine mutations return `Result` and roll back an in-memory change when saving
  fails.
- Implement `SyncStore::apply(&SyncStoreChanges)` as one atomic incremental transaction instead of
  replacing all state with `save`. `TreeNode` adds `name_undecryptable`, and stored sync metadata adds
  `change_anchor_floor`; initialize these fields in Rust literals. Old serialized state still reads.
- Conflict input now uses `VersionInfo::authenticated_version`, never a server content hash.
  Conflict deadlines return `Option<u64>`, and `keep_both_name` returns `Result` and requires a valid
  `HH.MM` time.
- `ConflictPolicy::DEFAULT` keeps both at once: a diverged file resolves to `AutoKeepBoth` when it is
  detected, whatever the clocks say, and its `deadline` is `None`. `NeedsUser` and a deadline come only
  from a policy with a non-zero `auto_resolve_after_secs`, so `conflict_state` reports `auto_keep_both`
  with no `decision_deadline`. `ConflictPolicy::DRIVE` names that policy, and `DEFAULT` is it.
- Name the drive's copy with `name_clash::drive_conflict_name`, for a name race and a sync conflict alike:
  `report (conflict, <device>).pdf`, then ` (2)`, ` (3)`. `keep_both_name` (`({device}, HH.MM)`) is
  unchanged and is no longer a drive name; the backup merge plan still uses it.
- `beebeeb-sync::SyncEngine::sync_once` now fails with `RemoteListingUnavailable`. Do not ship the
  legacy desktop prototype; build product sync on `beebeeb_core::sync`.

### Rust cryptography and authentication callers

- Normal OPAQUE login accepts only KSF version 1. Version 0 is available only through
  `client_login_finish_legacy_upgrade` after a trusted local migration decision; unknown versions
  fail. Immediately re-register migrated accounts as version 1.
- CLI-auth decryption accepts only the authenticated HKDF-derived ciphertext. Upgrade producers of the
  old raw-secret format.
- The passkey seal is a new 61-byte, versioned, account-and-credential-bound format whose version byte
  is also in the associated data. Existing 60-byte web blobs require an explicit migration and reseal;
  never reinterpret them. Recovery phrases are
  exactly 12 words.
- `MasterKey::to_bytes`, `combine_folder_link_key`, `OpaqueEnvelope::to_bytes`, OPAQUE finish secrets,
  and transfer shared secrets now use `Zeroizing` guards. The transfer helper is fallible and rejects
  low-order keys. Generic SAS derivation is fallible and rejects output above 8,160 bytes.
- Device link, QR path: `DeviceLinkQr::parse(scanned_text)` is the only constructor (`from_parts` is
  removed and `fingerprint()` is crate-private); the payload is `beebeeb-link:v2:` with the canonical
  device name after the session id and fingerprint (`DeviceLinkQr::device_name`,
  `matches_relayed_name`), and the unshipped `v1` is refused; `seal_for_new_device(qr, relayed_public,
  relayed_device_name, typed_code, material)` refuses a relayed name that differs from the scanned one
  before it seals; `beebeeb_client::devices::DeviceError::DeviceNameChanged`; the seal takes the new
  format; `NewDeviceLink::generate(session_id, device_name)` canonicalises the name
  (`canonical_device_name`), and `NewDeviceLink::open(sealed)` no longer takes the code.
- Device link, typed-code path: SPAKE2 with key confirmation in both directions over a transcript that
  binds the session, a fresh salt and the canonical device name (labels `…/v2`). The approver starts
  (`TypedCodeApprover::start(code, session_id, device_name)`), the new device answers
  (`NewDeviceLink::answer_typed_code` → `TypedCodeReceiver` and its message), the approver checks the
  answer (`confirm` → `ConfirmedTypedApproval`, `CoreError::Decryption` on a wrong code or a changed
  name) and only then seals; the new device checks the approver's tag in `TypedCodeReceiver::open`.
  `PakeSealedAccountKeyMaterial::from_parts(nonce, ciphertext)` drops the session id. Small-order
  peer elements are refused, and randomness failures are errors, not panics. `spake2` 0.4 does not
  wipe its copies of the code and scalars; the residual is documented in `device_link`. Replace the draft `beebeeb-api::proposed`
  request/answer types, rename `second_factor_required` to `authenticator_required`, and handle the
  exact locked-action allowlist.
- Key-proof servers may export/import the 64-byte verifier state between requests. Keep it only in an
  expiring secret store and never log it.
- `contact_keys::safety_number` now takes both parties' emails and keys and returns the 60-digit
  number (12 groups of 5) that web and the apps show: per party, the trimmed, lower-cased email and the
  key are hashed with 5200 SHA-512 rounds. `contact_keys::normalize_email` is the email form it uses.
  The vectors are `test-vectors/safety_number.json`, written by an independent Python generator.

### File-format, transfer, and storage integrators

- New content is v2. Names, thumbnails, and notes use purpose subkeys. All uploaders must move only
  after their readers support v2 and the purpose-specific metadata APIs; v1 remains readable.
- Protected encrypted metadata adds `version_id` and `version_counter`, which must appear together.
  `NameMetadata` adds `version`. Current-version readers must match frames to the authenticated
  metadata commitment; use the historical-version path for history. Raw-key metadata claiming v2 is
  rejected.
- A v2 version opens only against its record's commitment (Guus's ruling of 2026-11-07): every reader
  (`ChunkDecryptor`, `RangeOpener`, `RequestContentReader`) refuses a v2 frame 0 without one, with
  `CoreError::InvalidInput`. No released core wrote v2, so only development and test files are
  affected. `ChunkDecryptor::for_push`, `from_reader` and `for_push_with_file_key` read legacy v1 only.
  The commitment is threaded through `download::decrypt_frames_to` / `decrypt_chunks_to`,
  `encrypt::decrypt_chunks_to_file` / `decrypt_contiguous_to_file`, `file_encrypt::decrypt_chunks_to_file`,
  `zip::ZipEntry::version` and the `beebeeb-upload` download functions (`version:
  Option<VersionCommitment>`). New: `chunk_stream::open_recorded_chunk`,
  `EncryptedFileResult::version_commitment`, `RangeSessionError::MissingVersionCommitment` (refused
  before any request); `DownloadServiceError::MissingVersionCommitment` is now returned before any fetch.
- Production v2 upload resume always restarts: abandon the old session, initialize again, and upload
  from chunk zero. The one exception is `BackgroundUploadPlanner` continuing its own persisted v2
  version (same session, version id and counter) after the source and the staged-plaintext hash
  check; `BackgroundUploadPlanner::to_bytes` now takes `&mut self` and is the persistence point:
  `next_transfers` hands the OS only frames staged before the last `to_bytes`. `BackgroundUploadPlanner` constructors and restore now require authenticated file
  geometry and source identity; version-1 planner blobs are non-resumable.
- `DownloadRequest` requires a `MemoryBudget` and optional authenticated chunk size. `DownloadOutcome`
  and `AfterWriteCause` add handoff, `ApiMethod` adds `Put`, and background transports should override
  `DirectIo::storage_put_file`.
- `TransferState` adds `Paused` and `Cancelled`. `TransferFinished` adds
  `UploadTokenExpired { index }`; mint a fresh scoped token and requeue the staged ciphertext without
  spending a retry.
- A replacement upload's version counter is one above both the served metadata's counter and the
  store's remembered high-water mark, so a server serving an older record cannot make a counter repeat.
- `Store::open` creates the database 0600 and its directories 0700 on Unix and tightens an existing
  database and its `-wal`/`-shm`; the crate docs list what the plaintext cache holds.
- `beebeeb_store::atomic_publish` is removed. Publish relative to a
  `path_safety::TrustedDirectory` handle. The `store-test-helper` binary now requires the default-off
  `test-support` feature, which product builds must not enable.
- Range reads apply the same version rule as whole-file reads. `RangeOpener::new` takes the version
  commitment from the authenticated metadata after the pin, and `RangeRequest` adds `version` and
  `authenticated_chunk_size`. With a commitment, frame 0 opens only as that v2 upload, so an older
  upload of the same file is refused; a geometry with another stride than the authenticated one
  releases nothing.
- `backup::plan_merge` returns `Result`: a clash whose keep-both time is not `HH.MM` refuses the whole
  plan, because `keep_both_name` now validates the time. UniFFI `backup_plan_merge` reports it as
  `InvalidInput`.

### API, limits, and error consumers

- `ServerError::details` is removed. Use the bounded typed accessors for retry delay, trial cap, limit,
  and usage. New server fields require a typed accessor.
- Archive preview now has a 256 MiB hard ceiling and a 32 MiB convenience budget. Search shards clamp
  to 1 through 64 and typed search calls reject inputs over 4 KiB. A zero chunk count is invalid, and
  helpers that materialize one entry per chunk stop at 1,000,000; use streaming for larger valid files.
- Retry delays cap at 300 seconds. Invalid quota add-ons clamp to valid ranges with saturating
  arithmetic. `format_compact` clamps precision to 2 and `try_format_compact` rejects higher values.
- Direct `beebeeb-api` users must adopt typed onboarding/registration and recovery bodies, bearer
  recovery authorization, optional device approver keys, unknown-safe optional two-factor state, and
  the current device/login response models. `AuthError` adds fixed-label `InvalidAnswer` and
  `InvalidTransition` variants.
- Records that carry a secret redact it in `Debug`: TOTP setup, share links and shares, chunk
  manifests, file-request and stream tokens, signup tickets, email codes, pilot keys, push tokens, the
  data-export URL and key-proof tickets. The ones a person types or copies are also `Zeroizing`, which
  changes their type: `TotpSetup`'s `secret`, `qr_uri` and `backup_codes`, `CreateLink`'s
  `passphrase` and `token`, the client's `RecoveryChanges` codes and `AuthenticatorEnrollment`'s
  `qr_uri`. Wrap a `String` with `Zeroizing::new`.
- A request's `Debug` prints a header value only when the header is in `DEBUG_VISIBLE_HEADERS`;
  `Set-Cookie`, `Cookie`, `Authorization` and every other header print `[REDACTED]`.
- `ClientMetaField` adds `DeviceSettings = 7` and `ContactKey = 8`; codes 5 and 6 remain reserved.
  Sync `Op` literals add optional `device_id` and `created_at`.

### Web and cross-client fixture maintainers

- WASM `formatCompact` throws above precision 2; pass 0 through 2 and handle the exception. Rust's
  infallible formatter clamps instead.
- WASM device link: `sealDeviceLink(masterKey, scannedQr, relayedPublic, relayedDeviceName, typedCode)`
  takes the raw text the camera scanned, never session or fingerprint bytes, and throws
  `device_name_changed` when the relay's name differs from the scanned one (deny the link); show
  `scannedDeviceLinkName(scannedQr)`, never the relay's name; without a camera use the typed-code
  path, now exported: `WasmTypedApproval` (approver) and `WasmNewDeviceLink.answerTypedCode` →
  `WasmTypedReceiver` (new device). `new WasmNewDeviceLink(sessionId, deviceName)`; `publicFields()`
  returns `qr_payload` and `device_name` and no fingerprint; `open(approverPublic, nonce, ciphertext)`.
- WASM content decryptors take the object `decrypt_file_metadata[_with_key]` returned:
  `new WasmChunkDecryptor(masterKey, fileId, metadata)` and `fromFileKey(fileKey, fileId, metadata)`,
  and so does `decrypt_chunk_frame(fileKey, fileId, metadata, index, isLast, frame)`. A
  `chunk_format: 2` record without a version commitment throws; one with neither field opens v1 only.
- WASM `safetyNumber` and `normalizeEmail`: use them; JavaScript's `trim` differs from core's.
- Regenerate bindings for the protected metadata fields and update the shared vector fixture to version
  18, including the protected metadata and session key-proof vectors.
- WASM archives: `list_archive`, `decompress_gzip` and `list_tar_entries` are removed. Use
  `WasmArchiveSession` (range reads through `need_bytes`, the preview model, `openEntry`) and
  `WasmArchiveExtraction` (stage each file, upload it only on `file_end`, drop it on `file_skipped`).
  `zip`, `tar`, `tgz` and `gz` now preview on every platform (`previewableBatchFor`), so web shows the
  archive preview for all four. `checkPassword` can answer `damaged` (the entry's headers are damaged;
  the password cannot be judged). A protected file whose password passed its check byte but failed its
  CRC comes back as `file_skipped`, then `need_password` (`wrong`), then `file_begin` again for the
  same `node`: drop what was staged on `file_skipped` and stage afresh on the next `file_begin`.
  `supplyPassword` is taken only right after `need_password`; at any other time it is dropped.

### Added

- `beebeeb_core::archives`: one sans-I/O reader for zip, tar, tgz and gz (format by magic bytes, never
  the extension), WinZip AES (AE-1, AE-2) and ZipCrypto passwords (`ArchivePassword`: zeroized, not
  `Clone`, never logged), entry names through one rule set (zip-slip, device names, NFC, limits), the
  extraction planner (destination, clashes through `numbered_name`, quota, device space, Backups), the
  extraction step machine (a file is handed over only after its CRC-32 / authentication code passed),
  the preview screen model and all 63 words. Vectors: `test-vectors/archives_v1.json` and its fixtures,
  from the independent `gen_archives_v1.py`, under a drift guard. Bindings: `WasmArchiveSession`,
  `WasmArchiveExtraction`, `WasmExtractionPlan`; UniFFI records, `archive_list` and the native
  `ArchiveServiceHandle`.
- `beebeeb_client::downloads::DownloadService::read_range` / `range_reader` / `read_with`: plaintext
  ranges of v1 and v2 files through core's `RangeOpener` (frame 0 first, one recorded version), and
  `beebeeb_client::archives::ArchiveService` (one live service per temp root; it needs the application
  runtime). `UploadService::cancel_sources_matching` and `ClientRuntime::runs_tasks_alone`.
- `beebeeb_core::name_clash`: `ItemKind`, `TakenNames`, `numbered_name` ("Keep both": `report (2).pdf`,
  then `(3)`), `numbered_candidates` and `drive_conflict_name`. Names clash when their normalised forms
  are equal, and a candidate is cut so that the whole name fits in 255 bytes.
- `beebeeb_core::name_tag::normalize_for_tag`: `NFKC(simple_casefold(NFKC(name)))`, with simple case
  folding (statuses C and S) at Unicode 17.0.0; an empty name or one over 1024 bytes is refused
  (`NormalizeError`). Vectors: `test-vectors/name_clash_v1.json`, from an independent Python generator.
- `beebeeb-api`, `beebeeb-client`, and `beebeeb-store`, plus the native service-handle surface for
  authentication, devices, files, sync, transfers, thumbnails, sharing, contacts, settings, search,
  backup, File Provider, and coordinated sign-out.
- Native file services can restore a historical version while publishing fresh protected metadata
  with a rollback counter above every observed version. The API client now carries per-version
  metadata through the restore route, and Swift/Kotlin receive the resulting counter.
- Upload services support protected replacement uploads against an explicit base version. The new
  content commitment advances the previous protected counter, enabling the live replace/restore
  contract without falling back to v1 writes.

### Fixed

- `zip` moves from 8.6 to 9 (the writer only; `aes-crypto` in tests only), so RUSTSEC-2026-0367,
  -0368, -0369 and -0429 are no longer ignored in `.cargo/audit.toml`.
- Native requests declare `file-write-v2` and `version-metadata-v1` exactly where the server checks
  them: upload init, chunk, heartbeat and complete, and the direct upload grant and commit
  (`file-write-v2`), and file update and sync submit (`version-metadata-v1`). The request builder
  attaches the header only to routes flagged `Endpoint::capabilities`, never to every request. A v2
  file whose metadata predates version commitments remains readable until this device has observed a
  protected counter; stripping the commitment after that point is rejected as rollback.
- The file, upload and File Provider services ask core's Backups rules before every change: the row's
  own role first (`check_root_mutation`), then the app rule (`check_app_mutation`) in the app and the
  drive rule (`check_drive_mutation`) in the File Provider. A row's position is its depth below the
  row whose `system_role` is `backups_root`, read through its parents. Refusals are
  `FileServiceError::Protected` and `UploadServiceError::Protected`, with core's words. `BackupFolder`
  replaces `ManagedBackupFolder` and `BackupError::NotInBackups` replaces `UnmanagedFolder`. The
  backup pass's own uploads are not checked: it is the one writer the rules protect the tree for.
- An expired recovery attempt is `RecoveryState::Expired`, not `AuthError::MalformedAnswer`;
  completing it is refused with `RecoveryNotReady` before anything is sent.
- Backup scans page, deduplicate, export and enqueue lazily with a 64-upload cap. Failed and cancelled
  photo uploads retry at most three times, and successful completion is durable even when no backup
  completion handler is alive during a background wake.
- The native backup no longer uploads again a copy the person trashed or deleted, and no longer runs
  when the account was emptied: it stops on a `files_removed` or `backup_deleted` notice, or on a
  device or category folder that is trashed or gone, and skips the pass when the notices cannot be
  read. Before, trashing backup photos, or an emptied account, filled the account up again by itself.
- Sync: a remote rename is checked for a name clash in the item's own folder (its op carries no
  parent), and a move in its destination. Clashes compare core's normal forms (`TakenNames`) and the
  item that arrives second takes `drive_conflict_name` from its own name (`a (conflict, device).txt`:
  the writing device is not known by name on pull), never `a (2).txt`. A snapshot names clashing
  siblings the same whatever the server's order. Only core's decryption names an item from a remote
  op: a plaintext `name` / `new_name` in the server's payload is dropped, and a sealed name that does
  not open, or opens to a name the portable path rule refuses, is shown as undecryptable without
  stopping the sync. The engine's `apply_move` applies a client-added `new_name`.
- An offline delete from the Files app sends `file_trash` (the op the server accepts), so it reaches
  the server and moves the item to the Trash; it sent `file_delete`, which the server refuses.
- An upload is sized from its source as it is when the first pass starts, so a file that grew while
  queued is uploaded whole. The completion metadata is persisted before `complete` is sent, and an
  upload with it finishes by sending the same request (the server answers `already_completed`), so a
  crash after the server accepted it no longer fails the upload or uploads a backup photo twice.
- `DownloadService::video_range` reads through `RangeOpener` (frame 0 first, the geometry checked),
  the same release path as `read_range`.
- A UniFFI chunk decryptor, chunk encryptor or key handle whose lock was poisoned by a panic answers
  `CryptoError::InvalidInput` and drops its state, instead of panicking across FFI on every call.
- Durable uploads remove safe orphan ciphertext, count invalid saved state as a terminal attempt, keep
  partial staging resumable, and can finish after the platform removes the plaintext export once all
  chunks and the staged hash are committed.
- First-session crash markers no longer block a different account. Account-replacing native installs
  now require a one-shot authorization issued only after the service coordinator purges the old
  account's queues, caches, manifest, store, secrets and platform-owned data.

## [0.2.3] - 2026-11-07

Additive on v0.2.2: the first pass's baseline and the pass gate when the notices could not be read (LD-0121, spec
`2026-11-06-backup-from-source-design.md` Amendment 12c, Guus 2026-11-07 20:45). No v0.2.2 API is renamed,
retyped or removed.

### Added

- **`beebeeb_core::backup`**: `first_pass_baseline(setup_at_ms, legacy_last_backup_ms)`, the `last_pass_at_ms`
  of a device with none under the new engine: the moment backups were set up on this device, or an upgraded
  device's last successful backup under the old mirror engine; with both known the earlier (a later baseline
  hides more notices, so the earlier never lets an emptied account fill up again); with neither, 0 (any
  removal notice stops the backup). `backup_pass_gate(notices, last_pass_at_ms, listing)` with
  `BackupPassGate::{Run { stopped }, CheckFailed}`: when the notices could not be read (`None`), the pass
  uploads nothing, turns nothing off, keeps `last_pass_at_ms` and retries at the next scheduled pass, showing
  `MSG_STOP_CHECK_FAILED` ("Couldn't check — will retry.").
- **Bindings**: uniffi `backup_first_pass_baseline`, `backup_pass_gate` (`BackupPassGate` enum),
  `backup_check_failed_words` (3); wasm `backupFirstPassBaseline`, `backupPassGate`, `backupCheckFailedWords` (3).
- **Vectors**: `backup_plan.json` 117 → 128 cases (+5 baseline, 5 gate, 1 check-failed words).

## [0.2.2] - 2026-11-07

Additive on v0.2.1: the rebuild's clock rule (LD-0123), why a backup stops (LD-0121, spec
`2026-11-06-backup-from-source-design.md` Amendments 12, 12a and 12b), and the CLI-login ECDH moved off
RUSTSEC-2026-0387 (task 2378). No v0.2.1 API is renamed, retyped or removed.

### Added

- **`beebeeb_core::backup`, rebuild (LD-0123)**: `RebuildClock { offset_ms, margin_ms }` with
  `RebuildClock::UNKNOWN` and `copy_is_newer`; `records_from_remote_with_clock(remote, entries, clock)`:
  a copy counts only when `uploaded_at_ms > modified_ms + offset_ms + margin_ms`, with no offset known
  the one-sided 10-minute floor (`REBUILD_FLOOR_MS`); `rebuild_clock_from_date(date_header, sent_at_ms,
  received_at_ms)` measures the offset from a listing response's `Date` header (margin
  `REBUILD_MARGIN_BASE_MS` 2 s + the round trip; any failure gives the unknown clock).
- **`beebeeb_types::backup` (LD-0121)**: `BackupStopReason` (`backup_deleted`, `erase_request`,
  `account_lapsed`, `inactive_cleanup`, `account_reset`, `unknown_removal`, `unknown`), `NOTICE_FILES_REMOVED`,
  `NOTICE_BACKUP_DELETED`, and `BackupNotice` (the `notifications` row's `type` and `data`, ids only).
- **`beebeeb_core::backup`, stop (LD-0121)**: `backup_stop(notices, last_pass_at_ms, listing)` (Amendment
  12's steps 1-4: a newer `files_removed` notice turns every backup off, folders present or not; else per
  backup a `backup_deleted` notice naming this device's folder (and, for a category, its folder); else a
  folder gone with no notice, `unknown`; else nothing),
  `parse_backup_notice`, `ReceivedNotice`, `StopListing`, `StopFolder`, `StoppedBackup`, and the words:
  `backup_stop_words(reason, device, folder)`, `MSG_STOP_ERASE_REQUEST`, `MSG_STOP_ACCOUNT_LAPSED`,
  `MSG_STOP_INACTIVE_CLEANUP`, `MSG_STOP_ACCOUNT_RESET`, `MSG_STOP_UNKNOWN_REMOVAL`, `MSG_BACK_UP_AGAIN`
  ("Back up again"): Amendment 12's six lines as drafted are final (Guus 2026-11-07 19:04, G6).
- **The seventh line (LD-0121, spec Amendment 12b)**: a `files_removed` notice whose reason this build does
  not recognise (a future reason, or none) stops every backup as `BackupStopReason::UnknownRemoval`
  (`"unknown_removal"`) with `MSG_STOP_UNKNOWN_REMOVAL`, "Your files were removed, so backups are off.",
  never the `unknown` row's "was deleted" words; `parse_backup_notice`, `BackupNotice::reason` and the uniffi
  and wasm `backup_notice_reason` / `backupNoticeReason` give `unknown_removal` for it.
- **Bindings**: uniffi `backup_stop`, `backup_notice_reason`, `backup_stop_words`, `backup_again_action`
  (4); wasm `backupStop`, `backupNoticeReason`, `backupStopWords`, `backupAgainAction` (4).
- **Vectors**: `backup_plan.json` 71 → 117 cases (+6 rebuild clock, 22 stop, 10 notice, 7 words, 1
  action); every rebuild case now carries its clock.

### Changed

- `records_from_remote(remote, entries)` (signature unchanged) now applies `RebuildClock::UNKNOWN`: with no
  offset known a copy must be more than 10 minutes newer than the entry's mtime. Desktop main already calls
  it (its rebuild after a reinstall or the G4 adoption, pinned at v0.2.1): after a pin bump, and until desktop
  passes a measured clock to `records_from_remote_with_clock`, a rebuild uploads again every copy made within
  10 minutes of its file's last change (the safe direction, but a re-upload of most auto-backed-up files).

### Security

- **`p256` 0.13 → 0.14** (task 2378, RUSTSEC-2026-0387): the CLI-login ECDH (`cli_auth`) now runs on
  `elliptic-curve` 0.14.3 / `crypto-bigint` 0.7.10, which removes the secret-dependent branches the
  advisory lists. Wire format unchanged: the SEC1 encodings, the ECDH X-coordinate and the HKDF key are
  byte-identical (`tests/cli_auth_vectors.rs` passes with its constants untouched, and now also pins both
  public keys, checked against the independent pure-Python generator `test-vectors/tools/make_cli_auth_vectors.py`).
  `CliEphemeralKey::generate()` keeps 0.13's non-zero scalar (`NonZeroScalar::generate()`, rejection
  sampling). `crypto-bigint` 0.5.5 stays in `Cargo.lock` through `opaque-ke` 4.0.1 → `voprf` 0.5.0 →
  `elliptic-curve` 0.13.8 (no published `opaque-ke`, 4.1.0-pre.2 included, moves off it); core's OPAQUE
  suites are Ristretto255 and compile none of its arithmetic, but `cargo audit` still lists the advisory
  until `opaque-ke` moves.
- `beebeeb-wasm` adds `getrandom` 0.4 with `wasm_js`: p256 0.14 draws its randomness through it.

## [0.2.1] - 2026-11-06

Additive: backup rules (`beebeeb_core::backup`), the vocabulary (`beebeeb_types::backup`) and the
filesystem pass (`beebeeb-backup`). No v0.2.0 API changes. LD-0113, spec
`2026-11-06-backup-from-source-design.md` §4.

### Added

- **`beebeeb_types::backup`**: `SystemRole` (wire `"backups_root"`), `PROTECTED_FOLDER_ERROR`
  (`"protected_folder"`), `BACKUPS_ROOT_UNCLAIMABLE_ERROR` (`"backups_root_unclaimable"`),
  `ORIGIN_HEADER` (`"X-Beebeeb-Origin"`) and `ORIGIN_BACKUP` (`"backup"`), the header every request of
  a backup pass carries (spec Amendment 8; the server ignores it until phase 2), `Category` (keys and
  display names) and `Platform`.
- **`beebeeb_core::backup`** (pure: no I/O, no clock, no network):
  - layout: `ROOT_NAME` `"Backups"`, `MANIFEST_NAME` `".device.json"`, `backup_rel_path`;
  - protection (spec Amendments 7 and 8; a backup is written by its device's own backup and by
    nothing else): `Mutation` (`trash`, `delete`, `rename`, `move`, `create`, `write`; a move checks
    the row with `Move` and the destination folder with `Create`), `BackupPosition` (`Root`,
    `DeviceFolder`, `Manifest`, `CategoryFolder`, `Inside`, `Outside`) with
    `BackupPosition::at_depth(depth, name)` and `is_hidden_backup_item` (a device folder's manifest,
    never listed), and three rules with one set of words (`MSG_DELETE`, `MSG_MOVE`, `MSG_RENAME`,
    `MSG_MANAGED_IN_APP`, `MSG_READ_ONLY`, and `MSG_BADGE` "Read-only", the badge every client shows
    on the Backups root; Guus, "keep it Backups and just add a read-only badge"): `check_app_mutation` (web, desktop in the app,
    iOS, the CLI: the root and a device's manifest refuse everything; under the root a backup can be
    trashed or deleted and nothing else changes), `check_drive_mutation`
    (Explorer, Finder, the iOS Files app: nothing at or under the root changes; the root's words,
    then `own_backup_refusal` for the device's own active backups, then the rest) and
    `check_root_mutation` (the server's phase-1 rule: the root is never trashed, deleted, renamed or
    moved). The backup pass never goes through these rules;
  - skip rules: `skip_reason`, `SkipReason` (OS junk, library bundles, links, not-local entries
    and `.icloud` stubs, plus the client-set `Locked` and `TooLarge`, and the walk's `TooDeep`,
    `Unreadable` and `Excluded`);
  - device folders: `device_folder_name`, `device_id_from_machine_id` (label
    `beebeeb/backup-device-id/v1`), `find_device_folder` (by manifest id, legacy desktop adoption,
    create; an unreadable manifest is not mine and not adoptable). A device id is a string identity:
    a UUID or an iOS legacy id carried forward verbatim;
  - the manifest: `DeviceManifest`, `parse_manifest`, `serialize_manifest` (a real iOS manifest
    round-trips; unknown fields are kept, a folder entry's own included; only a document that is
    not a JSON object is unreadable: a bad field takes its default and a bad `folders` entry is
    dropped alone; a known field always wins over kept text of its name);
  - the root: `resolve_root` (use the flagged root, claim the oldest live `Backups`, or create) and
    `plan_merge` (legacy duplicate roots, depth unbounded, keep-both on a clash);
  - the pass planner: `plan_pass(entries, records, live_remote, live_remote_complete, unseen, held,
    budget)` (new, changed, unchanged, gone, unique moves, the budget, removed elsewhere only from a
    complete listing, a record missing from an incomplete listing is unknown and its work waits (a
    move whose signature an unknown record shares waits too), a changed file whose remote copy is
    gone uploads as new, a record whose copy is live again is held again, a record under an unseen
    key (raw, or by its folded key, NFC and case, when no entry has its exact key) is untouched,
    held keys skipped and not charged, the first upload always fits (`max_uploads` 0 counts as 1);
    each upload carries the paired `record_key` and, for a change, the `remote_id` it versions;
    each record to mark removed elsewhere is a `RecordRef` (key and remote id) for a
    compare-and-set), `folder_presence`,
    `records_from_remote` (exact key first, then the normalised key when unique), `normalize_key`,
    and the key helpers `file_name`, `parents` and `fold_name`;
  - custom folders: `custom_category_name` (safe like a device folder, never equal to a fixed
    category or another custom folder: ` (2)`, ` (3)`; at most 200 bytes with the suffix and a
    reserved stem's `_`, the base is cut, never the suffix) and `category_folder_name`.
- **`beebeeb-backup`** (new crate, for desktop and the CLI): `walk_source(root, exclude)` (never
  opens a file, never follows a link, never descends into what is not local (the backed-up folder
  itself included: a not-local root is one skip, never listed) or into an excluded
  path such as the client's own sync root; attributes from the directory listing only; a folder is
  listed whole or reported unreadable; depth cap 64; a root whose path holds `..` is
  `InvalidInput`), `fingerprint`, `attrs_of`, and
  `run_pass(host, root, exclude, category, budget)` over the `BackupHost` trait the client
  implements (it re-reads an entry whose listing differs from its record, checks what can fail
  before it changes anything, and on Windows and macOS never creates a folder that differs from
  an existing one only in case or normalisation). `BackupHost::mark_removed_elsewhere` is
  compare-and-set on the key and remote id the pass read: a record a finishing upload rewrote
  meanwhile is left alone. `BackupHost::put_record` (after a move) re-keys the record the pass read,
  keeping the fields stored now, or stores the moved record when no record names that remote file
  any more; it answers whether it stored, and a move it left alone counts as deferred. Every request a host makes for a pass carries
  `ORIGIN_HEADER: ORIGIN_BACKUP`.
- **Bindings**: uniffi `backup_*` (16 functions, among them `backup_check_root_mutation`,
  `backup_check_app_mutation`, `backup_check_drive_mutation`, `backup_position_at_depth`,
  `backup_is_hidden_item`, `backup_root_badge`, `backup_root_name` and `backup_origin_header`;
  every unknown string is `InvalidInput`) and wasm `backupCheckRootMutation`,
  `backupCheckAppMutation`, `backupCheckDriveMutation`, `backupPositionAtDepth`,
  `backupIsHiddenItem`, `backupRootBadge`, `backupProtectionMany`, `backupParseManifest` (8).
- **Vectors**: `test-vectors/consolidation/backup_{protect,device,root,plan}.json` (163, 57, 21 and
  71 cases, counted with `python3 -I -c "import json,sys; [print(p, len(json.load(open(p))['cases'])) for p in
  sys.argv[1:]]" test-vectors/consolidation/backup_*.json`; `check-backup-vectors-generated.sh` guards them in
  CI), run by `cross_client_vectors`, with independent Python generators in
  `test-vectors/tools/make_backup_*_vectors.py`.

## [0.2.0] - 2026-11-06

### Breaking and behaviour changes

- **`owned_keys::resolve_owned_key` signature changed** to six arguments: takes `name_encrypted`
  and, for a plaintext-named file, `first_chunk`. The old five-argument form and `foreign_added`
  are removed; the id class now decides. `ResolvedOwnedKey` gains `name` and `write_target`.
  Callers must add the two new arguments.
- **`kdf::wrap_owner_file_key` / `unwrap_owner_file_key` now refuse a non-foreign id.** L8 is
  adoption-only. Any call that passes an owner id must switch to a foreign id.
- **`ChunkDecryptor::{from_reader, for_push, for_push_with_file_key}` and several decrypt helpers
  now require `ExpectedChunkFormat` and/or the file id.** Affected: `encrypt::decrypt_chunks_to_file`,
  `encrypt::decrypt_contiguous_to_file`, `file_encrypt::decrypt_chunks_to_file`,
  `zip::ZipEntry` (new `chunk_format` field), `beebeeb_upload::{decrypt_downloaded_bytes,
  download_and_decrypt_file, DownloadClient::download_and_decrypt}`, and the UniFFI/WASM
  equivalents. `chunk_stream::open_chunk` now also takes the version id. Callers must read
  `ExpectedChunkFormat` from the file's authenticated metadata (`decrypt_name_metadata`) and
  pass it on every decrypt call.
- **`encrypt::decrypt_file_metadata[_with_key]`** (new, for files): a plaintext `name_encrypted`
  is now refused. Use `decrypt_name_metadata` for folders; use `decrypt_file_metadata` for files.
- **`DownloadPlanner` verdict ordering changed**: a file keeps the strongest verdict received
  (`Corrupt` > `Terminal` > `Restart` > `ApiForFile`); once set, a weaker answer can no longer
  override it. Stale, repeated, or out-of-order window answers no longer downgrade a verdict.
- **Discovery authorization answers (401/403) no longer count toward the routing-failure budget**
  and no longer disable direct discovery for ten minutes on repeated refusals. Reauthentication
  leaves cached discovery and real transport failures unchanged.

### Added

- Range reads for streaming hydration (LD-0105, core PR #71): `chunk_stream::RangeOpener`
  opens one authenticated frame at any index under the file's one geometry and version id;
  `direct_transfer::range::RangePlanner` grants windows at any start (chunk 0 first, then
  demands, then read-ahead), aging out idle grants without spending renewals; `range_session`
  in `beebeeb-transfer` hands each authenticated 4 KiB piece to the system; `RangeLessor`
  bounds the shared memory budget: at most four sessions hold a lease at once; together their
  ciphertext in flight is at most max(256 MiB, k × (chunk_size + 28)) for k active sessions,
  plus one plaintext chunk per session (256 MiB at 32 MiB chunks, up to 1 GiB at 128 MiB chunks). New test vectors:
  `test-vectors/direct_range.json`, generated and drift-guarded in CI.
- `beebeeb-transfer`, the L2 driver crate for direct S3 downloads (task 2173, plan K2):
  `download()` drives core's `DownloadPlanner` over any `DirectIo` transport (API calls,
  bounded storage GETs, the pinned per-chunk route, injected sleep and clocks), decrypts
  chunks in order through `ChunkDecryptor`, writes plaintext only after a chunk authenticates,
  and reports `Done(stats)` or `UseApi(reason)`. Body checks go through core's `StorageBody`
  (`from_head` / `push` / `finish`); a signed URL never reaches an event, error or `Debug`
  string; `DirectStore` shares discovery and breaker health per `(api_base, account_id)`.
  `test_support::ScriptedIo` and a conformance suite (`test-support` feature) check a
  transport's redirect, cookie, credential, idle/total timeout and bounded-body behaviour
  in-process. No tokio or reqwest in normal dependencies.
- Item id classes (task 2275 L12-L14): `item_id::new_foreign_item_id` / `is_foreign_item_id` /
  `item_class` and the core-minted `item_id::NewItemId` (`owner()` v4, `foreign()` v8). Foreign ids
  are RFC 9562 UUID v8 with the RFC 4122 variant in canonical lowercase hyphenated text; any other
  text form is `InvalidInput`. `kdf::wrap_owner_file_key` / `unwrap_owner_file_key` now refuse a
  non-foreign id (L8 is adoption-only), and every export inherits that. `owned_keys::resolve_owned_key`
  takes the id class from the id, authenticates the served name, ignores owner wraps for owner rows
  and returns a `KeyOrigin`, the resolved name and a `WriteTarget` (id + key + pin) for writable rows;
  `DerivedUpperRepair` rows stay read-only with no target. New sealers: `encrypt_name_for_new_item` /
  `encrypt_name_for_target`, `encrypt_note_for_new_item` / `encrypt_note_for_target`,
  `encrypt_thumbnail_for_new_item` / `encrypt_thumbnail_for_target`, and
  `ChunkEncryptor::for_push_for_new_item` / `for_push_for_target`; the old write entry points remain
  and are documented as deprecated for writes. `owned_keys::resolve_request_row` resolves a 2236
  request row (content under `C`, name under a derived key or `C`, read-only) and
  `owned_keys::child_wrap_matches` does the L14 constant-time child-wrap check. WASM exports
  `newForeignItemId`, `newOwnerItemId`, `isForeignItemId`, `resolveOwnedKey`, the six `*ForNewItem` /
  `*ForTarget` sealers, `resolveRequestRow`, `childWrapMatches`; UniFFI exports
  `MasterKeyHandle.resolve_owned_key` / `resolve_request_row`, `FileKeyHandle.child_wrap_matches`,
  `new_foreign_item_id`, `new_owner_item_id`, `is_foreign_item_id`. Vectors version 14 adds
  `item_ids` and re-publishes the L8 owner-file-key vector under a foreign id (vendored copies must
  be refreshed: web `test/core-vectors-kat.test.ts`, mobile `CoreVectorsKATTests.swift` and
  `CoreVectorsKATTest.kt`).
- `onboarding` module (task 1744): password-policy evaluator driven by the server's numbers
  (floored at the shipped 12), k-anonymity breached-password helper (hashing and matching
  only; no I/O, no third-party endpoint, fail-open or fail-closed as the server declares), and
  the signup ceremony state machine over the existing recovery-phrase and OPAQUE primitives.
  Exposed through native Rust, WASM (`WasmBreachCheck`, `WasmSignupCeremony`,
  `evaluate_password`) and UniFFI (`BreachCheckHandle`, `SignupCeremonyHandle`,
  `evaluate_password`). New dependency: `sha1` (corpus addressing only). The ceremony takes a
  `BreachCheck` bound to the password (never a bare verdict), treats an empty or oversized
  breach-endpoint body as an outage, exposes `wipe()` (`abandon()` in the bindings) and
  `email_changed()`, and floors the password minimum at the shipped 12.
- `direct_transfer` module (task 2173): the client-side rules of the direct S3 transfer contract
  v1 as pure Rust (no I/O, no clock): wire types, the storage-link authority check
  (`check_storage_url`, `redact`, `scrub`), the API-answer classifier, the download window
  planner and the discovery cache. Exposed through native Rust, WASM (`WasmDownloadPlanner`,
  `WasmDirectDiscoveryCache`, `checkStorageUrl`, `classifyDirectAnswer`, `parseDirectDiscovery`,
  `redactUrl`, `scrubText`, `directTransferConstants`) and UniFFI (`DirectDownloadPlannerHandle`,
  `DirectDiscoveryCacheHandle`, `direct_check_storage_url`, `classify_direct_answer`,
  `parse_direct_discovery`, `direct_redact_url`, `direct_scrub_text`, `direct_transfer_constants`).
  Stable `code()`/`kind()` names on `Refusal`, `Call`, `Outcome`, `Violation`, `PlanError`,
  `Verdict`, `Poll`. `test-vectors/direct_transfer.json` is run by core, the WASM seams and the
  UniFFI exports through one interpreter (`direct_transfer::vectors`, `test-support`).
  `Call::PinnedChunk` classifies the pinned per-chunk route (any 409 except a held file is a gone
  pin; `Outcome::Retry` for what may pass) and `PinnedRetry::decide` is the shared retry policy
  (WASM `pinnedRetryDecision`, UniFFI `direct_pinned_retry_decision`).
- Direct upload rules (task 2173, `direct_transfer::upload`): what a client may believe of the
  server's `object-upload-v1` answers and how hard it tries one chunk before the file goes back to
  the API. `UploadGrant::from_answer`, `UploadCommitted::from_answer`, `put_stored`,
  `UploadChunkState` (`UploadChunkPolicy`: at most 4 grants per chunk; the 8th failure ends the
  tries, 7 are ridden out; 150 s of waiting in all; the client's own backoff is 1 s doubling with
  equal jitter, `UploadChunkState::with_seed` takes one random seed per chunk), `UploadFailure`,
  `UploadNext`; `Call::UploadGrant` and `Call::UploadCommit` in `classify`, with two new outcomes:
  `Outcome::Regrant` (a commit `409 chunk_not_stored`: ask for a new link) and `Outcome::Held` (a
  commit `409 commit_in_progress`: the server's commit lock, which after a failed copy lives
  `COMMIT_LOCK_TTL` = 420 s). A hold is not a failure: it is waited out on an allowance of its own
  (`hold_budget` = TTL + 30 s, polls of 5 s doubling to 15 s with equal jitter, or the stated
  wait) that leaves the failure cap and the retry budget alone. A 1xx/3xx on an upload call is
  `ApiForThisFile` (a wrong path: the session cannot go direct); only "no answer" may pass. A hold
  never polls faster than once a second (a stated 0, or a 0/negative/NaN millisecond count from a
  binding, is raised to 1 s) and is capped at 450 polls; `UploadChunkState::new` (seed 0) exists in
  test builds only. Both new outcomes are exported through
  WASM (`DirectOutcomeJs`) and UniFFI (`DirectOutcomeDto`; `Held { millis: Option }`); the Swift,
  Kotlin and header bindings are regenerated, and the docs of `Retry` and `ApiForThisFile` now say
  what they mean for an upload (do not hand an upload outcome to `direct_pinned_retry_decision`).
  Test vectors: 58 more `classify` rows in `direct_transfer.json` (63 -> 121, run by core, the WASM
  seams and the UniFFI exports) and the new `direct_upload.json` (24 grant answers, 8 commit
  answers, 5 init `transport` rows, 27 policy scenarios, the server constants it copies with their
  source lines), which is read by `upload.rs`'s tests ONLY. Every upload row names its source (a test enforces it); the vector files are generated by
  `test-vectors/tools/` (with `jitter_port.py`, the independent port of the jitter rule); 33 of the
  90 grant/commit/classify upload rows are the server's own status and body on that call at server main 30c8ed62; the
  others say what they are: 14 what a proxy or the framework sends (a bare 404, an HTML page, a
  redirect), 11 client-side cases (a server answer that exists but not on that call, or the agreed server change after #338: 503 `storage_unavailable` + `Retry-After` for the R3.4 transients, `commit_in_progress` + `Retry-After` = the lock's remaining TTL), 32 synthetic. Core's copies of the 4-grant cap and the lock TTL are pinned to
  that file; the server does not read it, so a server change turns no test red until the server
  adds its own assert.
  Not yet exported through WASM or UniFFI as functions: the CLI uses the Rust module directly;
  desktop, iOS and web adopt it in their own tasks.
- Direct transfer, the download side for web, desktop and iOS (task 2173, clients plan A1, A2 and the
  download half of A3; no upload behaviour changes):
  - `direct_transfer::timeouts`: the time bounds every client applies (`STORAGE_CONNECT_TIMEOUT` 15 s,
    `STORAGE_GET_IDLE` 30 s, `DISCOVERY_TIMEOUT` 15 s, `API_CALL_TIMEOUT` 60 s,
    `BACKGROUND_PUT_RESOURCE_TIMEOUT` 240 s) and `storage_put_total` / `storage_get_total`
    (`60 s + ceil(len / 131072) s` over the ciphertext length). A test keeps the PUT total under the
    server's late-write fence `max(300, ceil(len * 8 / min_uplink) + 60)` for every chunk length up to
    the largest chunk; the server numbers are recorded with their source lines in
    `test-vectors/direct_upload.json` `constants`.
  - `direct_transfer::health`: `DirectHealth` and `Direction`. After a transfer gave up direct, no new
    one of that direction starts for one trust period (ten minutes); `may_start_file` also keeps a file
    that gave up off direct for the rest of its life; `last_gave_up_ms` / `restore` persist the two
    timestamps; a recorded time in the future counts as expired.
  - `direct_transfer::resume`: `resume_transport(recorded, discovery, forced_api)`. A recorded direct
    upload session is given up only on a definite no (the user forced the API, discovery lists no
    upload, a JSON 404), never because discovery could not be read this time; a 401/403 keeps the
    record and asks for a new login.
  - `DownloadPlanner`: a storage breaker (`storage_given_up()`): when a chunk uses up its renewals and
    no chunk of the transfer has come whole from storage, the rest of the file goes through the pinned
    API route (the existing `api_only` mode) and the caller records `gave_up(Download)`; the report is
    cleared if a chunk already in flight then arrives from storage. A fetch through
    the pinned route is not a storage success. And a byte ceiling on held chunks
    (`PlannerConfig::max_in_flight_bytes`, `set_max_in_flight_bytes`): the reorder window becomes
    `clamp(floor(bytes / (chunk_size + 28)), 1, 4)`; `None` keeps today's four.
  - Exports. WASM: `WasmDirectHealth`, `resumeTransport`, `storagePutTotalMs`, `storageGetTotalMs`,
    `WasmDownloadPlanner.setMaxInFlightBytes` / `storageGivenUp`, and five `*_ms` time bounds in
    `directTransferConstants()`. UniFFI: `DirectHealthHandle`, `direct_resume_transport`,
    `direct_storage_put_total_ms`, `direct_storage_get_total_ms`,
    `direct_background_put_resource_timeout_ms`, `DirectDownloadPlannerHandle.set_max_in_flight_bytes` /
    `storage_given_up`, and the same five bounds in `DirectConstantsDto` (the Swift and Kotlin bindings
    are regenerated).
  - Vectors: `direct_transfer.json` gains `health` (8 scenarios, 37 steps) and `resume_transport` (20
    rows) sections and 16 planner scenarios (the breaker, the byte cap, a client clock ten minutes off);
    `direct_upload.json` gains the time-bound constants and two policy rows showing a refused PUT (403)
    and a PUT with no answer (status 0) are decided alike. Each surface (core, WASM, UniFFI) runs them
    all through the one interpreter.
- CI `Claims guard` job: runs the shared claims-guard engine plus
  `scripts/claims-guard/canon-sweep.sh`, the canon CLAIM_SWEEP over the whole tree
  (including any `design/` folder), so a false audit or compliance claim fails the build.

### Changed

- **Breaking:** `owned_keys::resolve_owned_key(master, item_id, owner_wrap, folder_wrap, name_encrypted,
  first_chunk)` replaces the five-argument form; `foreign_added` is gone (the id class decides) and
  `ResolvedOwnedKey` gains `name` and `write_target`. Callers must pass the served `name_encrypted`
  and, for a plaintext-named file, its chunk 0.

- `kdf::owner_file_key_for_name` with `kdf::OwnerKeyConvention` (`String`, `Binary`,
  `UpperRepair`): resolves an owner's per-file key from the `(file_id, name_encrypted)`
  pair and reports which id convention it came from. The repair convention reads files the
  iOS File Provider sealed under an uppercase id (SF-0002) and is READ-ONLY — a client that
  gets `UpperRepair` must not rename or write a new version, only save edits as a new file.
  `kdf::owner_file_key_for_content` does the same per content version from that version's
  first chunk frame (v1 legacy `nonce || ciphertext || tag`, or core's v2 frame 0), because
  a Files-app edit could seal a later version under the lowercase id while the name and the
  first version stayed under the uppercase one. A file is read-only if EITHER its name or ANY
  version reports `UpperRepair`. Both resolvers accept only the canonical lowercase
  hyphenated UUID form. The shared master-key readers (`decrypt_name_metadata`,
  `decrypt_name_with_mime`, and therefore `decrypt_file_metadata` / `decrypt_name` /
  `decrypt_names`) deliberately do NOT gain the uppercase candidate: they stay
  two-convention (string, then binary), so a client that only bumps core cannot mistake an
  uppercase-sealed file for a writable one. WASM `ownerFileKeyForName` /
  `ownerFileKeyForContent`, UniFFI `MasterKeyHandle.owner_file_key_for_name` /
  `owner_file_key_for_content` returning `OwnerFileKey`. Nothing writes under the uppercase
  convention; no row is re-sealed or migrated. Vectors `upper_repair_v1` and
  `upper_repair_split_v1` (vectors version 13).
- Link labels and guest actor names (task 2275, L16): `kdf::wrap_link_label` /
  `unwrap_link_label` seal a link's display label to the master key under
  `HKDF-SHA256(master, "beebeeb-link-label-v1" || share_id)` with the same string as AAD; the label
  is NFC and 1..40 Unicode scalar values after NFC. `kdf::seal_folder_actor_name` /
  `open_folder_actor_name` seal a guest's name under
  `HKDF-SHA256(folder key, "beebeeb-folder-actor-name-v1" || root_id)` with the same string as AAD.
  Both sides of the actor name apply ONE rule, `kdf::sanitize_actor_name`, and the writer seals its
  result, so core never seals a name its own opener refuses: (1) NFC; (2) strip every `Cc`
  character and U+00AD, U+061C, U+180E, U+200B, U+200E, U+200F, U+2028-U+202E, U+2060-U+2064,
  U+2066-U+206F, U+FEFF, U+FFF9-U+FFFB, while keeping U+200C ZWNJ, U+200D ZWJ, the variation
  selectors and the tag characters U+E0020-U+E007F (Persian and Indic spelling, emoji ZWJ
  sequences and subdivision flags need them); (3) NFC again; (4) refuse a leading combining mark;
  (5) 1..64 scalars, counted after steps 1-4; (6) refuse a visibly blank name, one with no
  character that is neither whitespace nor an invisible filler (Hangul fillers, U+2800, U+034F,
  the Mongolian and other variation selectors, Khmer inherent vowels, U+1D173-U+1D17A, ZWNJ, ZWJ,
  the tags, and every other Default_Ignorable_Code_Point that is not stripped). The writer refuses
  with `InvalidInput`; the openers normalize instead of refusing non-NFC plaintext, and refuse
  anything else they cannot display with `Decryption`; a non-16-byte id is `InvalidInput`. The
  actor-name envelope is a JSON text value with exactly the keys `cipher_suite`, `nonce` and
  `ciphertext` (all required, none `null`, no other or repeated key); key order and JSON
  whitespace are free, so a hop that re-encodes the JSON keeps it openable.
  `kdf::open_legacy_child_key` is the one legacy unbound child opener (60-byte frame, no AAD)
  and refuses a 32-byte plaintext that is valid UTF-8; a genuine random legacy child key that
  happens to be UTF-8 (about 2^-30) is refused and reads as a wrong key (accepted L9 residual,
  recorded on the function). WASM `wrapLinkLabel` / `unwrapLinkLabel` / `sealFolderActorName` /
  `openFolderActorName` / `openLegacyChildKey`; UniFFI `MasterKeyHandle.wrap_link_label` /
  `unwrap_link_label` and `FileKeyHandle.seal_folder_actor_name` / `open_folder_actor_name` /
  `open_legacy_child_key`. Test vectors are version 16 (`link_label_v1`, `folder_actor_name_v1`,
  `legacy_child_refusal_v1`); version 14 is main's `item_ids` set alone, and 15 is not used (it
  named an earlier draft of these vectors on the unmerged branch). Vendored copies must be
  refreshed to 16: web `test/core-vectors-kat.test.ts`, mobile `CoreVectorsKATTests.swift` and
  `CoreVectorsKATTest.kt`.
- `direct_transfer::storage::check_storage_get`: a storage GET delivered the chunk only for a
  `200` whose `Content-Length` is exactly the grant's length; anything else is `Failed { status }`
  (status `0`: no HTTP answer). `check_storage_body` applies the same rule to the bytes actually
  counted (a truncated stream after a good head is still failed). `StorageGet::kind()` is the stable
  `"stored"`/`"failed"` name bindings and vectors print. WASM `checkStorageGet` / `checkStorageBody`,
  UniFFI `direct_check_storage_get` / `direct_check_storage_body`.
- `direct_transfer::pacing::paced_until_ms`: desktop's download-ceiling formula (`kbps` is KiB/s,
  `kbps == 0` is `i64::MIN`, saturating), so the direct path can hold requests back instead of
  sleeping after each chunk. WASM `pacedUntilMs` crosses numbers as `f64` and reports the no-ceiling
  case as `-Infinity` (test with `Number.isFinite`); UniFFI keeps `i64`/`u64`.
- `direct_transfer::context`: `MemoryClass` with `max_in_flight_bytes` (256 MiB native, 64 MiB
  browser, 64 MiB mobile app, 16 MiB mobile extension) and `pairs_allowed` (the direction must be
  offered and every discovery storage pair allowlisted; hosts ASCII case-insensitive, buckets
  exact, and a discovery that lists no pairs is refused rather than allowed vacuously). WASM
  `maxInFlightBytes` / `pairsAllowed`, UniFFI `DirectMemoryClassDto` / `direct_max_in_flight_bytes`
  / `direct_pairs_allowed`.
- `WasmDownloadPlanner.chunkLength(index)` and `DirectDownloadPlannerHandle::chunk_length(index)`:
  the ciphertext length of a chunk from the accepted window's geometry (`null`/`None` before it).
- `directTransferConstants()` / `DirectConstantsDto` gain the response caps
  `max_discovery_body_bytes` (256 KiB), `max_grant_body_bytes` (1 MiB) and `max_chunk_body_bytes`
  (256 MiB + 28), so no client re-types them.
- Contract vectors `test-vectors/direct_transfer.json`: `storage_get` (13 rows: 10 heads and 3 counted bodies), `pacing` (7),
  `pairs_allowed` (12) and `memory_class` (4), each row naming its `source`; `vectors::run_all`
  checks them on native, WASM and UniFFI.
- Pure direct-upload pipeline planner (task 2173 C1-C2): one PUT lane per file, bounded
  commit overlap and ciphertext retention, per-chunk retries, separate ack/hold waits,
  interrupt draining, and grant-version-aware replay handling. Shared PUT totals scale
  with concurrent PUTs while staying thirty seconds below the server fence. This exposes
  Rust rules only; client drivers and the combined upload bindings follow separately,
  and the server's upload flag remains off.
- Direct transfer bindings (task 2173; the surface is unreleased, so this is breaking only for a branch that
  already read it): the presigned link of a `fetch` step is an OBJECT, not a string, so that no habitual
  logging shows its signature. WASM: `WasmSignedUrl` (`raw()` is the link; `redacted()`, `toString()` and
  `toJSON()` are scheme and host); `poll()` is typed `DirectPoll` in the `.d.ts`. UniFFI: `DirectSignedUrl`
  (redacted `Display`/`Debug`, hence Swift `description` and Kotlin `toString()`; `DirectSignedUrl(url:)`
  builds one for an app's tests), and `DirectChunkGrantDto.url` is one. Read the
  link with `.raw()` and pass that to the HTTP client, nothing else. Notes for consumers:
  - A `WasmSignedUrl` holds a pointer into wasm memory and is not structured-cloneable: `structuredClone` /
    `postMessage` gives `{ __wbg_ptr: <number> }`, no methods and no link. Send a worker the string
    `step.url.raw()` at the moment it fetches.
  - Kotlin: `toString()` of a `DirectSignedUrl`, or of a record holding one, throws `IllegalStateException`
    once it has been `destroy()`ed or `close()`d (as any call on a released object does).
  - `DirectSignedUrl`, `DirectChunkGrantDto` and `DirectPollDto` export no `Eq` or `Hash`, on purpose.
    UniFFI 0.31.1's generated Kotlin `equals` and `hashCode` lower the object's handle with no check that it
    was destroyed, so comparing or hashing a released link, grant or poll would be a use-after-free in native
    code. The Swift types that hold the link are therefore not `Equatable` or `Hashable`; compare the links'
    text (`raw()`). A test pins that the generated Kotlin has no `equals`/`hashCode` that lowers a handle.
  - The constructor adds one FFI function; the four generated binding files are regenerated.
- `DownloadPlanner`: a file that comes to more than one verdict keeps the strongest: `Corrupt` > `Terminal` >
  `Restart` > `ApiForFile`, and among equals the first. Every writer (`window_answered`,
  `window_answered_bytes`, `window_malformed`, `window_failed`, `api_fetch_failed`, `chunk_unauthentic`)
  goes through one setter, so a stale or repeated window answer or a failure reported out of order can no
  longer turn a chunk that does not authenticate, a revoked grant or a changed version into "use the API".

### Fixed

- Discovery authorization answers (401/403) no longer consume or extend the routing-failure
  budget. Reauthentication leaves cached discovery and real transport failures unchanged;
  repeated authorization refusals no longer disable direct discovery for ten minutes.
- `beebeeb-wasm`: the generated `beebeeb_wasm.js` and `beebeeb_wasm.d.ts` did not parse since core #34
  (`SyntaxError: Illegal break statement`). The driver example in the `WasmDownloadPlanner` doc comment
  used inline `/* ... */` comments; wasm-bindgen copies doc comments into a JSDoc block, whose first inner
  closer ended it early. The example now uses `//` comments, and `beebeeb-wasm/js-tests/run.sh` loads the
  real module under node so `cargo test` is no longer the only judge of the JS surface; it also `node --check`s
  the glue of both wasm targets and `tsc --noEmit`s the `.d.ts` files, in the new CI job `wasm-js`. A test in
  `beebeeb-wasm` and `beebeeb-uniffi` fails on any block-comment token in a `///` doc comment.

### Removed

- `design/hifi/`: a stale snapshot of UI mockups committed with the initial import. Its mockup
  copy claimed that this code had been externally audited (naming a security firm and a date)
  and named the EU Digital Operational Resilience Act as a fit. Neither was ever true: `core`
  has **not** had an external audit (see "Audit status" in the README). The mockups live in
  the private design workspace; this repo is the crypto core.

### Security

- Chunk format v2 (task 1908): core now reads chunk format v2. File-content frames carry position
  as AES-GCM associated data — `"beebeeb/chunk/v2" || len(file_id) || file_id || version_id(12) ||
  chunk_index || is_last` (STREAM construction) — and are sealed under a dedicated chunk subkey
  `HKDF-SHA256(file_key, "beebeeb/chunk/v2/key")` that no other blob type uses. `version_id` is
  the random nonce of the upload's frame 0, so frames of two uploads (versions) of one file id
  cannot be mixed. v1 frames, which every client still writes, carry no associated data, so a
  malicious server can reorder, duplicate, drop, truncate or splice them undetected. Same frame layout and sizes;
  the server is unaffected. `chunk_stream::WRITE_FORMAT` stays `V1Legacy`: every client still
  WRITES v1 until all clients' read paths are on this core; flipping it is a separate, gated
  release (task 1908). Files written today still carry no position binding.
- Every file-content reader now REQUIRES an `ExpectedChunkFormat` taken from the file's
  encrypted metadata (`encrypt::decrypt_name_metadata[_with_key]`): `V2` accepts only v2 frames,
  so a server can no longer pass a same-key no-AAD blob (encrypted name, thumbnail) off as a
  one-frame v1 file; `Unrecorded` (metadata without a format: files from before the switch) lets
  frame 0 decide. Readers reject out-of-order frames, frames from another upload, frames after
  the last chunk, and fail at `finish()`/EOF when a v2 file ended early. A zero-frame body is now
  an error (it used to decrypt to an empty file). Uploads record the format with
  `encrypt::encrypt_name_with_chunk_format` (`"chunk_format": 2`); `encrypt_name` output is
  unchanged.
- Breaking: `ChunkDecryptor::{from_reader, for_push, for_push_with_file_key}`,
  `encrypt::decrypt_chunks_to_file`, `encrypt::decrypt_contiguous_to_file`,
  `file_encrypt::decrypt_chunks_to_file`, `zip::ZipEntry` (new `chunk_format` field),
  `beebeeb_upload::{decrypt_downloaded_bytes, download_and_decrypt_file,
  DownloadClient::download_and_decrypt}` take the file id and/or the expected format;
  `chunk_stream::open_chunk` takes the version id. UniFFI: `decrypt_chunks_to_file`,
  `decrypt_contiguous_to_file`, `download_and_decrypt_file`, `MasterKeyHandle.decrypt_file`,
  `ChunkDecryptorHandle.{from_file, for_push, for_push_with_file_key}` take
  `expected_chunk_format` (0 = unrecorded, 2 = v2); `FileKeyHandle.decrypt_chunk_frame` takes
  `version_id`. WASM: `WasmChunkDecryptor` constructors take `expectedChunkFormat`;
  `decrypt_chunk_frame` takes `version_id`. New: `ExpectedChunkFormat`,
  `ChunkDecryptor::{version_id, format, chunks_decrypted, finish}`, `encrypt::{NameMetadata,
  decrypt_name_metadata, decrypt_name_metadata_with_key, encrypt_name_with_chunk_format}`,
  UniFFI `ChunkDecryptorHandle.{for_push_with_file_key_handle, version_id, chunk_format,
  finish}`, `MasterKeyHandle.{encrypt_name_with_chunk_format, decrypt_name_metadata}`,
  `FileKeyHandle.decrypt_name_metadata`, WASM `encrypt_name_with_chunk_format`,
  `decrypt_name_metadata[_with_key]`, `WasmChunkDecryptor.versionId`. Feature `test-support`
  (dev-dependencies only) exposes `ChunkEncryptor::with_format` to tests.
- Metadata domain separation (task 1908 review round 3): name/MIME envelopes and thumbnails can
  now be sealed under their own subkeys, `HKDF-SHA256(file_key, "beebeeb/name/v1")` and
  `HKDF-SHA256(file_key, "beebeeb/thumb/v1")`, so neither can ever open as file content (v1 or
  v2) or as each other. Every name reader (`decrypt_name*`, `decrypt_names`,
  `decrypt_*_metadata*`) and the new `encrypt::decrypt_thumbnail` try the subkey first, then the
  legacy raw file key, so every stored blob keeps opening. Writing: a name that records
  `chunk_format: 2` is always subkey-sealed; everything else follows
  `encrypt::METADATA_SEAL_WRITE`, which is tied to `WRITE_FORMAT` and stays `Legacy` during the
  read-only phase (clients not yet on this core must keep reading the names this core writes).
- `encrypt::decrypt_file_metadata[_with_key]` (task 1908 review round 3): the metadata reader for
  FILES. Same as `decrypt_name_metadata`, but a plaintext (non-JSON) `name_encrypted` is refused:
  a plaintext name carries no chunk-format pin, so a server could otherwise swap a v2 file's
  metadata for a plaintext name and re-enable frame-0 detection. Folders keep using
  `decrypt_name_metadata`.
- Resumed uploads (task 1908 review round 3): `chunk_stream::{SessionResume, resume_policy}` and
  `ChunkEncryptor::resume_policy`. A v2 upload's frames all bind one version id (frame 0's
  nonce), and a resumed upload builds a new encryptor with a new one, so continuing the old
  server session would store an unreadable mix. Only a v1 session resumed by a v1 encryptor may
  continue; anything else, including a resume record that does not say which format it holds,
  must restart from chunk 0 in a fresh session. Clients persist `ChunkEncryptor::format` next to
  the session id.
- New bindings: UniFFI `MasterKeyHandle.decrypt_file_metadata`,
  `FileKeyHandle.{decrypt_file_metadata, encrypt_thumbnail, decrypt_thumbnail}`,
  `ChunkEncryptorHandle.resume_policy` + enum `SessionResumeAction`; WASM
  `decrypt_file_metadata[_with_key]`, `encrypt_thumbnail`, `decrypt_thumbnail`,
  `WasmChunkEncryptor.resumePolicy`. `kdf::derive_file_subkey` is public.
- Replace / new version honours the file's recorded pin (task 1908 review round 4, I-1):
  `ChunkEncryptor::with_recorded_pin(pin)` writes v2 frames for a file whose encrypted metadata
  records v2, even while `WRITE_FORMAT` is still v1 (the server keeps a file's metadata on
  replace, so a v1 new version of a v2-pinned file would never open); `Unrecorded` keeps
  `WRITE_FORMAT`. One rule for content, names and thumbnails: `chunk_stream::chunk_format_for_pin`
  + `encrypt::metadata_seal_for` (`METADATA_SEAL_WRITE = metadata_seal_for(WRITE_FORMAT)`).
  New `encrypt::encrypt_thumbnail_for(file_key, plaintext, pin)` (a v2 pin is always
  subkey-sealed). Bindings: UniFFI `ChunkEncryptorHandle.apply_recorded_pin`,
  `FileKeyHandle.encrypt_thumbnail_for`; WASM `WasmChunkEncryptor.withRecordedPin`,
  `encrypt_thumbnail_for`. Restart path for resumed v2 uploads documented (abandon or lease
  expiry before re-init; never the old session on a 409).
- File notes get their own subkey (task 1908 review round 5): web sealed `note_encrypted` with
  `encrypt_metadata` under the raw file key, in the same envelope shape as a legacy name, so a
  server could serve a note as a v2 file's `name_encrypted` (read as a name with no pin) and then
  as its only frame (a one-frame v1 file), undoing the v2 pin. New
  `encrypt::{NOTE_KEY_INFO, encrypt_note, encrypt_note_for, decrypt_note}`: notes are sealed under
  `HKDF-SHA256(file_key, "beebeeb/note/v1")` with the same rule as names and thumbnails (a v2 pin
  is always subkey-sealed; `Unrecorded` follows `METADATA_SEAL_WRITE`), returned as the canonical
  `EncryptedBlob` JSON; `decrypt_note` tries the note subkey, then the legacy raw key. Bindings:
  UniFFI `FileKeyHandle.{encrypt_note, encrypt_note_for, decrypt_note}`; WASM `encrypt_note`,
  `encrypt_note_for`, `decrypt_note`. Clients must write and read notes through these (web
  `file-details-panel.tsx` follow-up).
- `with_recorded_pin` / `apply_recorded_pin` / `withRecordedPin` docs: `V2` only with the pin
  read from an existing file's authenticated metadata; a new file uses `WRITE_FORMAT` (doctest).

## [0.1.0] - 2026-05-13

### Added
- AES-256-GCM file encryption and decryption
- Argon2id key derivation for password-based encryption
- X25519 Diffie-Hellman key exchange for folder sharing
- OPAQUE protocol for zero-knowledge authentication
- BIP39 mnemonic recovery phrase generation and verification
- Constellation erasure coding for distributed storage redundancy
- Desktop sync engine with filesystem watcher and conflict resolution
- WASM bindings for browser-based encryption
- UniFFI bindings for native mobile integration

### Changed
- Nothing yet.

### Fixed
- Nothing yet.

### Removed
- Nothing yet.

### Security
- Zero-knowledge architecture: server never sees plaintext data or keys
- All key material zeroized after use via the `zeroize` crate
