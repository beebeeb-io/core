# Binding exports

`beebeeb-wasm` is the JavaScript/WebAssembly surface. `beebeeb-uniffi` is the Swift and Kotlin surface.
The Rust source annotations are authoritative; generated artifacts are build outputs and can vary by
toolchain.

## Compatibility policy

The workspace is pre-1.0. Version `0.3.0` contains breaking API and binding changes. Consumers must pin
one core revision, regenerate or replace generated bindings from that revision, and update call sites
before moving the pin. Export counts are not an API guarantee.

Prefer opaque handles and operation-specific readers or sealers. Request-row results use
`RequestContentReader` and `WasmRequestContentReader`; they do not return the row's content key. A
sequential decryptor is a single-consumer ordered cursor, so callers create a fresh decryptor for a new
read sequence.

## Default UniFFI surface

Native applications start with `NativeClientHandle`. It owns the typed client, selected runtime and
Rust Keychain backend; it never exposes the generic request executor or an account token. Its service
objects are:

| Area | Binding objects |
| --- | --- |
| Account | `AuthServiceHandle`, `AuthChallengeHandle`, `PasswordAcceptedHandle`, `DeviceServiceHandle`, opaque device-link/approval, recovery, signup and authenticator handles |
| Files and sync | `FileServiceHandle`, `FilePageHandle`, `SyncServiceHandle`, `EventStreamHandle`, `FileProviderServiceHandle` |
| Transfers | `UploadServiceHandle`, `DownloadServiceHandle`, `ThumbnailServiceHandle`, `BackupServiceHandle` |
| Sharing and local data | `ShareServiceHandle`, `ContactServiceHandle`, `SearchServiceHandle`, `SettingsServiceHandle` |
| Persistence | `StoreHandle` |
| Lifecycle | `ServiceCoordinatorHandle`, one-shot `AccountReplacementHandle` |
| Cryptographic operations | `MasterKeyHandle`, `FileKeyHandle`, `ChunkEncryptorHandle`, `ChunkDecryptorHandle`, `RequestContentReader`, item/write-target handles and purpose-specific sealers |

App-facing values use records such as `FileData`, `UploadData`, `DownloadData`, `SearchResultData`,
`DeviceSettingsData` and `EngineEventData`. Failures use `ServiceError` and existing purpose-specific
binding errors. `DownloadData` has no caller-supplied version counter; downloads read the counter from
authenticated encrypted metadata. Transfer runners take `NetworkSignal`, while Wi-Fi and upload staging limits
come from `DeviceSettingsData`; transfer clocks stay inside Rust. Upload, download and thumbnail factories no longer
take a `MasterKeyHandle`: all three resolve a generation-bound `SessionKey` from `NativeClientHandle` at operation
time and reject results from a replaced session. `RuntimeProfile::Lightweight` selects the current-thread runtime for
extensions.

`SyncServiceHandle.refresh_snapshot()` performs first sync and `recover_gap(catch_up_limit)` rebases
after a sequence gap. `FileProviderServiceHandle.changes_since` reports an expired anchor as the typed
`ServiceError::AnchorExpired` case. `ServiceError` also preserves managed-by-service, quota (including
limit and usage), cancellation, session-expired and retry-after cases instead of flattening them.

Platform work crosses the callback interfaces `SecretStoreCallback`, `PasskeyPrompt`,
`ImageCodecCallback`, `ChunkTransport`, `AssetSourceCallback`, `BackupManifestStoreCallback`,
`DomainNotifierCallback`, `PlatformTransferCancellerCallback` and `AccountDataPurgerCallback`. Secret
storage itself is performed by Rust; the secret-store callback authorizes access and receives no secret
bytes.

`AssetSourceCallback.snapshot(kind, cursor, limit)` is paged and returns `next_cursor`; its records do
not contain eager export paths, and `export(kind, local_identifier)` is called only for assets selected
for the bounded upload queue. Backup upload
completion is recorded by Rust, so `BackupServiceHandle.upload_completed` is no longer exported.
`ContactServiceHandle.observe` and `accept` fetch the contact public key in Rust and no longer accept
key bytes from the application. `NativeClientHandle.service_coordinator` takes the shared `StoreHandle`
so Rust wipes account rows before the platform removes directories and any still-open database file.

`NativeClientHandle.sign_out_this_app` and `DeviceServiceHandle.sign_out_whole_device` both require a
`ServiceCoordinatorHandle`. They stop account work, cancel platform transfers, clear service caches and
the backup manifest, purge account directories, then remove session state in the required order. The
whole-device form also enforces the last-device confirmation input.

Account replacement first calls `NativeClientHandle.prepare_account_replacement`, which requires the
last-device warning confirmation and the same cancellation and purge callbacks. It returns a one-shot
`AccountReplacementHandle` only after coordinator cleanup succeeds; every `*_replacing_account`
installer consumes that handle. A boolean alone can no longer replace an account. `FileServiceHandle`
also exposes `restore_version(store, file_id, version_id)`, returning the fresh authenticated rollback
counter when the restored file has protected version metadata.

Device approval supports QR and typed-code paths with opaque one-shot state and a separate
acknowledgement. Recovery, signup/recovery-kit output, authenticator enable/remove, password and email
change, session revoke and account deletion are also service operations; no session token, account key
or authenticator secret has a binding getter. `RuntimeProfile::Lightweight` plus the File Provider
factory opens a targeted store-backed engine and does not load the whole tree.

The account changes a signed-in session makes (`AuthServiceHandle.setup_authenticator`,
`enable_authenticator`, `remove_authenticator`, `change_password`, `change_email` and
`request_account_deletion`) keep the server's answers apart. A password the step-up did not confirm is
`ServiceError::Authentication`, and a refused step-up never reads as an expired session.
`ConfirmationRequired` (confirm the password again), `SecondFactorRequired` (call again with the
authenticator or a backup code), `SecondFactorRejected` (that code was not accepted),
`DeletionAlreadyScheduled`, `SubscriptionActive` and `EmailNotSent` (the deletion link could not be
sent; nothing changed) are their own cases, and `ServiceErrorKind` has the same six. A delay the server
sends only as a `Retry-After` header is `RetryAfter { seconds }`, as one in the body is. A 401 on these
operations' other requests is `SessionExpired`.

Signup methods exist so the web-declared client and contract tests can drive the shared ceremony;
native client declarations receive the typed web-only refusal and URL. Stored sessions share the
owner, master key, API URL, generation, and device identity, but keep one token per configured app id.
App and whole-device sign-out therefore remain distinct coordinator operations.

Password sign-in on a device returns a locked `PasswordAcceptedHandle` after any authenticator step;
it has no retained-password or login-email-code retry state. The next path is QR/typed device approval,
passkey plus an email code, or recovery key plus an email code. Every path finishes with account-key
proof; the passkey and recovery paths submit their email ticket only at proof finish.
`create_passkey_copy`, `open_with_passkey`, QR approval and
typed approval take the account and key from `NativeClientHandle` instead of accepting caller-supplied
values. Replacing another locally stored account uses the explicit `*_replacing_account` methods and
the coordinator-issued replacement handle; the ordinary install methods return
`AnotherAccountOnDevice` without consuming the accepted sign-in state.

## Legacy UniFFI feature

`legacy-bindings` is off by default and is the only feature that links `beebeeb-upload`. It retains the
old comparison-app surface while that app migrates. The feature adds:

- Raw-key records and free functions: `MasterKeyResult`, `RecoveryPhraseResult`, `OpaqueStartResult`,
  `OpaqueLoginFinishResult`, `derive_master_key`, `derive_file_key`, `generate_recovery_phrase`,
  `recover_from_phrase`, `opaque_registration_start`, `opaque_registration_finish`,
  `opaque_login_start`, `opaque_login_finish`, `derive_x25519_private`, `derive_x25519_public`,
  `x25519_shared_secret`, `derive_share_key`, `compute_recovery_check`, `folder_key_id`,
  `derive_request_wrap_key`, `wrap_request_private`, `unwrap_request_private`, `seal_to_request` and
  `open_request_upload`.
- Generic raw-key operations: `encrypt_chunk`, `decrypt_chunk`, `decrypt_chunks_to_file`,
  `decrypt_contiguous_to_file`, `encrypt_metadata`, `decrypt_metadata`, `encrypt_name`, `decrypt_name`,
  `decrypt_name_with_mime`, `encrypt_blob`, `decrypt_blob`, `derive_sas_bytes`, `transfer_derive_key`,
  `transfer_derive_sas_bytes` and `transfer_sas_to_words`.
- Raw constructors/accessors: `MasterKeyHandle::from_keychain_bytes`,
  `MasterKeyHandle::derive_x25519_private`, `MasterKeyHandle::export_for_keychain`,
  `FileKeyHandle::from_key_bytes` and `ChunkDecryptorHandle::for_push_with_file_key`.
- Token-based transfer wrappers: `upload_encrypted_file` and `download_and_decrypt_file`, including
  their progress callbacks, result records and `UploadError`.

New native code must not enable this feature. It calls the service handles and purpose-specific key
handles instead.

## WASM surface

The web binding remains a browser-focused, I/O-free surface. Its exports cover file/name/version
formats; push chunk sealers and readers; thumbnail, note and metadata sealers; sign-in and onboarding
cryptography; device-link and key-proof state; request-row and owned-key resolution; API/retry/direct
transfer descriptors; path/media/preview decisions; share-link formats; encrypted client metadata; and
local search-index synchronization. The web host performs plain API transport.

Existing browser byte-key entry points remain compatibility surface because browser storage is not yet
handle-based. New device-security exports are `WasmNewDeviceLink`, `sealDeviceLink`,
`WasmTypedApproval`, `WasmTypedReceiver`, `answerSessionKeyProof` and the purpose-specific
`apiDescriptor`; the approved account key stays in an opaque `WasmAccountKeyMaterial`. No native service uses the browser byte-key entry points, and new WASM
exports must not return a raw key.

## Breaking changes from the crypto review (0.3.0)

Each change closes a review finding; the old form is removed, not deprecated.

### WASM

| Export | Before | Now |
| --- | --- | --- |
| `sealDeviceLink` | `(masterKey, sessionId, fingerprint, relayedPublic, typedCode)` | `(masterKey, scannedQr, relayedPublic, relayedDeviceName, typedCode)`: the raw text the camera scanned; core parses it. Never build that text from server data. A relayed name that differs from the scanned one throws `device_name_changed` before anything is sealed. |
| `scannedDeviceLinkName(scannedQr)` | none | the new device's name from the scanned QR: the name to show, never the relay's |
| `new WasmNewDeviceLink` | `(sessionId)` | `(sessionId, deviceName)`; the name is canonicalised (`device_name` in `publicFields()`) |
| `WasmNewDeviceLink.publicFields()` | `{session_id, public_key, fingerprint}` | `{session_id, public_key, device_name, qr_payload}`: render `qr_payload` (`beebeeb-link:v2:`, with the device name) as the QR; no fingerprint bytes leave core |
| `WasmNewDeviceLink.open` | `(typedCode, sessionId, recipientPublic, approverPublic, nonce, ciphertext)` | `(approverPublic, nonce, ciphertext)`: the link supplies its own session id and key |
| `WasmNewDeviceLink.answerTypedCode(approverMessage)` | none | the new device's typed-code answer: a `WasmTypedReceiver` (`message` to relay, then `open(nonce, ciphertext)`) |
| `new WasmTypedApproval(typedCode, sessionId, deviceName)` | none | the approver's typed-code side: relay `message`, show `deviceName`, `confirm(newDeviceMessage)` (throws `confirmation_failed` for a wrong code or a changed name, `malformed_answer` for a bad message), then `seal(masterKey)` → `{nonce, ciphertext}`; nothing is sealed before `confirm` succeeds |
| `new WasmChunkDecryptor` | `(masterKey, fileId, expectedChunkFormat)` | `(masterKey, fileId, metadata)`: the object `decrypt_file_metadata` returned; its commitment is enforced |
| `WasmChunkDecryptor.fromFileKey` | `(fileKey, fileId, expectedChunkFormat)` | `(fileKey, fileId, metadata)`, from `decrypt_file_metadata_with_key` |
| `decrypt_chunk_frame` | `(fileKey, fileId, versionId, index, isLast, format, frame)` | `(fileKey, fileId, metadata, index, isLast, frame)`: the record's commitment names the one upload whose frames open; never chunk 0's bytes |
| `normalizeEmail(raw)` | none | core's email normalisation; web never trims an email itself. The safety number a share shows is `shareSafetyNumber` |
| `apiDescriptor` | | adds `get_device_link_pake_for_approver`, `pending_device_links`, `get_device_link`, `approve_device_link`, `deny_device_link` |

### UniFFI

| Export | Before | Now |
| --- | --- | --- |
| `DeviceServiceHandle.approve_device_link` | `(id, qr: DeviceLinkQrData, typed_code)` | `(id, scanned_qr: String, typed_code)`; `DeviceLinkQrData` is removed. A relay name that differs from the scanned one is `ServiceError::Authentication` and denies the link |
| `DeviceServiceHandle.scanned_device_link_name(scanned_qr)` | none | the new device's name from the scanned QR: the name to show, never the pending link's `device_name` |
| `DeviceLinkHandle.qr()` | `DeviceLinkQrData` | removed: `qr_payload()` is the text to render, `device_name()` the canonical name |
| `DeviceLinkHandle.begin_typed_path()`, `TypedDeviceLinkHandle`, `TypedDeviceLinkStartData` | the new device spoke first | removed: the approver speaks first; the new device calls `answer_typed_path(approver_message)` → `TypedDeviceLinkAnswerData { handle, outbound_message }` |
| `TypedDeviceApprovalStartData` | `{handle, outbound_message}` | adds `device_name`, the name the new device's confirmation must match |
| `DeviceServiceHandle.approve_typed_device_link` | sealed after the exchange | checks the new device's confirmation first; a wrong code or a changed name is `ServiceError::Authentication` and denies the link |
| `ChunkDecryptorHandle.from_file` | `(master_key, file_id, expected_chunk_format, chunk_size_bytes, input_path)` | `(master_key, file_id, metadata: NameMetadataDto, chunk_size_bytes, input_path)` |
| `ChunkDecryptorHandle.for_push` | `(master_key, file_id, expected_chunk_format)` | `(master_key, file_id, metadata: NameMetadataDto)` |
| `ChunkDecryptorHandle.for_push_with_file_key_handle` | `(file_key, file_id, expected_chunk_format)` | `(file_key, file_id, metadata: NameMetadataDto)` |
| `ChunkDecryptorHandle.for_version_with_file_key_handle` | none | `(file_key, file_id, expected_chunk_format, version_id, version_counter)` for key-handle holders |
| `ChunkDecryptorHandle.for_push_with_file_key` (`legacy-bindings`) | `(file_key, file_id, expected_chunk_format)` | `(file_key, file_id, metadata: NameMetadataDto)` |
| `FileKeyHandle.decrypt_chunk_frame` | `(file_id, version_id, index, is_last, format, frame)` | `(file_id, metadata: NameMetadataDto, index, is_last, frame)` |
| `MasterKeyHandle.decrypt_file` | `(file_id, expected_chunk_format, chunk_paths, output_path, callback)` | `(file_id, metadata: NameMetadataDto, chunk_paths, output_path, callback)` |
| `decrypt_chunks_to_file`, `decrypt_contiguous_to_file`, `download_and_decrypt_file` (`legacy-bindings`) | `expected_chunk_format: u8` | `metadata: NameMetadataDto` in its place |
| `RecoveryChangesData`, `PasskeyPromptResult.prf_output` | `String` / `Vec<u8>` | `SecretString` / `SecretBytes`: still `String` and `Data` / `ByteArray` in Swift and Kotlin, wiped and redacted on the Rust side |
| `normalize_email(raw)` | none | core's email normalisation. The safety number a share shows is `share_safety_number` |
| `ServiceError` of the account changes (`AuthServiceHandle`: authenticator, password, email, deletion) | every failure, an expired session included, was `Unavailable` | a wrong step-up password is `Authentication`; new `ConfirmationRequired`, `SecondFactorRequired`, `SecondFactorRejected`, `DeletionAlreadyScheduled`, `SubscriptionActive`, `EmailNotSent` (and the same `ServiceErrorKind` cases); `RetryAfter` also takes a `Retry-After` header |

A decryptor refuses a missing record or half a commitment (`version_id` without `version_counter`, or
the reverse). A record with neither field is legacy metadata: it opens v1 content only. Since Guus's
ruling of 2026-11-07 ("refuse v2 without commitment") a `chunk_format: 2` record without a commitment is
refused when the reader is built, and an unrecorded one refuses a v2 frame 0. No released core wrote v2,
so only development and test files are affected.

### Rust (round 3)

| Item | Before | Now |
| --- | --- | --- |
| `ChunkDecryptor` (every constructor), `RangeOpener`, `RequestContentReader::open_frame` | v2 opened without a commitment | a v2 frame 0 opens only against a commitment; `RangeOpener::new` refuses a v2 pin without one; the refusal is `CoreError::InvalidInput` |
| `ChunkDecryptor::for_push`, `from_reader`, `for_push_with_file_key` | read v1 and v2 | read legacy v1 only (no commitment); read v2 with `for_current_version`, `from_reader_for_current_version` or `for_version_with_file_key` |
| `chunk_stream::open_recorded_chunk(file_key, file_id, metadata, index, is_last, frame)` | none | the record-driven random-access open the bindings use |
| `download::decrypt_frames_to`, `download::decrypt_chunks_to` | `(…, expected, chunk_count, …)` | `(…, expected, version: Option<VersionCommitment>, chunk_count, …)` |
| `encrypt::decrypt_chunks_to_file`, `encrypt::decrypt_contiguous_to_file`, `file_encrypt::decrypt_chunks_to_file` | `(…, expected, …)` | `(…, expected, version: Option<VersionCommitment>, …)` |
| `zip::ZipEntry` | no commitment | `version: Option<VersionCommitment>` |
| `file_encrypt::EncryptedFileResult::version_commitment(previous)` | none | the commitment to seal for the written version |
| `beebeeb_upload::download_and_decrypt_file`, `DownloadClient::download_and_decrypt`, `decrypt_downloaded_bytes` | `(…, expected, …)` | `(…, expected, version: Option<VersionCommitment>, …)` |
| `beebeeb_transfer::RangeSessionError::MissingVersionCommitment` | none | a v2 pin without a commitment, refused before any request |
| `beebeeb_client::downloads::DownloadServiceError::MissingVersionCommitment` | defined, unused | returned before any fetch for a `chunk_format: 2` record without a commitment |
| `DeviceLinkQr` | `parse` of `beebeeb-link:v1:` (session id, fingerprint) | `parse` of `beebeeb-link:v2:` (session id, fingerprint, canonical device name); `device_name()`, `matches_relayed_name(name)`; a `v1` payload is refused |
| `seal_for_new_device` | `(qr, relayed_public_key, typed_code, material)` | `(qr, relayed_public_key, relayed_device_name, typed_code, material)`: a relayed name that differs from the scanned one is refused before anything is sealed |
| `beebeeb_client::devices::DeviceError::DeviceNameChanged` | none | QR path: the relay's name differs from the scanned one; the link is denied |

## Verifying a release

- Build native binding crates with `cargo build -p beebeeb-uniffi -p beebeeb-wasm`.
- Regenerate Swift and Kotlin with the `uniffi-bindgen` commands in `build-ios.sh` and
  `build-android.sh`; generated files are never hand-edited.
- Build the web target with `wasm-pack build beebeeb-wasm --target web` and run
  `beebeeb-wasm/js-tests/run.sh`.
- Compare generated declarations and headers with the consumer-facing change notes. Do not infer
  compatibility from an export count alone.

## Backup rule exports (0.2.1)

LD-0113 (backups from the real folder, a protected Backups root, backup rules
in core). Base: tag `v0.2.0` (`3db0cc26f286`). Additive only: nothing in v0.2.0
is renamed, retyped or removed.

### WASM

Counts are the `export function` / `export class` names in the generated
`beebeeb_wasm.d.ts` (`wasm-pack build beebeeb-wasm --target web`), which is
what a bundler sees: `grep -c "^export function\|^export class" beebeeb_wasm.d.ts`,
and `comm` over the sorted names for the added and removed lists.

- base (`v0.2.0`): 149 names
- head: 157 names
- **removed: 0**
- **added: 8** (the eight `backup*` names below)

| Name | What |
| --- | --- |
| `backupCheckAppMutation(position, mutation)` | The app rule, the web's own (spec Amendment 8): core's words when `mutation` (`trash`, `delete`, `rename`, `move`, `create`, `write`) of a row at `position` (`root`, `device_folder`, `manifest`, `category_folder`, `inside`, `outside`; for `create`, the destination folder) is refused, else `undefined`. The root and a device's manifest refuse everything; under the root only trash and delete are allowed. |
| `backupCheckDriveMutation(position, ownActiveSource, mutation)` | The drive rule (Explorer, Finder, the Files app), same words: the root's words, then the own-active-backup words, then "Backups are managed in the Beebeeb app…" or "Backups are read-only…" for anything at or under the root, else `undefined`. |
| `backupCheckRootMutation(role, mutation)` | The server's root rule: the root's words for a trash / delete / rename / move of the `backups_root` row, else `undefined`. |
| `backupPositionAtDepth(depth?, name)` | A row's position from its depth below the flagged root (`undefined`: not under it) and its name (`manifest` for a device folder's `.device.json`). |
| `backupIsHiddenItem(depth?, name)` | `true` for a row no listing shows (a device folder's `.device.json`). |
| `backupRootBadge()` | The badge shown on the Backups root, `"Read-only"`. |
| `backupProtectionMany(roles: string[])` | One byte per listing row, 1 = the protected root (one crossing per listing). A role this build does not know is protected (1), never a throw. |
| `backupParseManifest(json)` | A decrypted `.device.json` as a plain object; unknown fields kept. |

Every unknown mutation, position or role string throws, except in
`backupProtectionMany`. Dialog copy (the device-folder confirmation) stays in
the web UI. The web client keeps the row's `system_role` from the listing and
passes it here.

### UniFFI

Counts are the `uniffi_beebeeb_uniffi_fn_*` and `uniffi_beebeeb_uniffi_checksum_*`
symbols in the generated `beebeeb_uniffiFFI.h` (`uniffi-bindgen generate
--language swift` over the built library), base against head:
`grep -c -E "uniffi_beebeeb_uniffi_(fn|checksum)_" beebeeb_uniffiFFI.h`, and `comm`
over the sorted symbols.

- base (`v0.2.0`): 576 symbols
- head: 608 symbols
- **removed: 0**
- **added: 32** (16 functions, each with its checksum)

| Function | What |
| --- | --- |
| `backup_check_app_mutation(position, mutation)` | `throws -> String?`: the app rule (the iOS app), the refusal words or none; `position` from `backup_position_at_depth`, for `create` the destination folder; the root and a device's manifest refuse everything |
| `backup_check_drive_mutation(position, own_active_source, mutation)` | `throws -> String?`: the drive rule (Files app), same precedence as core |
| `backup_check_root_mutation(role, mutation)` | `throws -> String?`: the server's root rule |
| `backup_position_at_depth(depth, name)` | `"root"`, `"device_folder"`, `"manifest"` (a device folder's `.device.json`), `"category_folder"`, `"inside"` or `"outside"` (`depth` none) |
| `backup_is_hidden_item(depth, name)` | `true` for a row no listing shows (the manifest) |
| `backup_root_badge()` / `backup_root_name()` | `"Read-only"`, the badge shown on the Backups root; `"Backups"`, the name of a root made on `BackupRootPlan.Create` |
| `backup_origin_header()` | `BackupHeader { name: "X-Beebeeb-Origin", value: "backup" }`, sent on every request of a backup pass |
| `backup_skip_reason(name, is_dir, is_link, not_local)` | Why an entry is never backed up, or none |
| `backup_resolve_root(candidates)` | `BackupRootPlan`: `Use`, `Claim { id, merge_from }`, `Create` |
| `backup_plan_merge(survivor, duplicates, clash_label, hhmm)` | `[BackupMergeStep]` from flat listing rows; pass `hhmm` with a dot |
| `backup_device_folder_name(raw, my_id, taken)` | The device folder name, with the device-id suffix on a collision; ids are strings (a UUID or an iOS legacy id) |
| `backup_find_device_folder(me, candidates)` | `BackupDeviceFolderChoice`: `Existing`, `AdoptLegacy`, `Create { name }`; a manifest that does not parse is "unreadable" (not mine, not adoptable), never an error; a legacy non-UUID id matches `Existing` |
| `backup_parse_manifest(json)` / `backup_serialize_manifest(manifest)` | `.device.json`; unknown fields cross as `other_json` (the manifest's, and each `BackupFolderState`'s own); only a document that is not a JSON object fails to parse |
| `backup_plan_pass(entries, records, live_remote, live_remote_complete, unseen, held, max_uploads, max_bytes)` | `BackupPassPlan` with `held` and `deferred_unknown`; each upload carries `record_key` and, for `changed`, `remote_id`; `mark_removed_elsewhere` is `[BackupRecordRef]` (key and remote id): mark a record only while it still names that remote id; `max_uploads` 0 counts as 1 (iOS passes an empty `unseen` and asset ids with `/` replaced by `\|`) |

Every string the binding parses (mutation, position, role, platform, record
state, id) that it does not know is `CryptoError.InvalidInput`, never a pass.

The committed `beebeeb-uniffi/bindings/` copy is regenerated by `build-ios.sh`
/ `build-android.sh` on the platform rung; this branch does not commit it.
Before this branch it was already behind v0.2.0's source (43 functions of
v0.2.0 are missing from the committed header), so a regeneration also brings
those in.

### Rust (rustdoc JSON, private items included)

`beebeeb_core` +211 items, `beebeeb_types` +33, `beebeeb_uniffi` +439 (the
uniffi scaffolding behind the 16 exports), `beebeeb_wasm` +13; **0 removed and 0
changed** in all four (rustdoc JSON of `v0.2.0` and of this branch, pinned
1.96.0, item paths compared). New crate: `beebeeb-backup`.

## Backup stop and rebuild clock exports (LD-0121 and LD-0123)

LD-0123 (the rebuild's clock rule) and LD-0121 (why a backup stops, and its
words: spec `2026-11-06-backup-from-source-design.md` Amendments 12 and 12a).
Base: tag `v0.2.1` (`a5413d2049f5`). Additive only: nothing in v0.2.1 is
renamed, retyped or removed.

### WASM

Counts are the `export function` / `export class` names in the generated
`beebeeb_wasm.d.ts` (`wasm-pack build beebeeb-wasm --target web --dev
--no-opt`, base tree and head tree), which is what a bundler sees, and `comm`
over the sorted names for the added and removed lists.

- base (`v0.2.1`): 157 names
- head: 161 names
- **removed: 0**
- **added: 4**

| Name | What |
| --- | --- |
| `backupStop(notices, lastPassAtMs, listing)` | Which backups turn off on this pass, and why (Amendment 12, steps 1-4): `[{category, reason}]` in category key order, `[]` when nothing changes. `notices`: the `notifications` rows `{type, data, created_at_ms}` (a row that is not a backup notice is skipped whatever its shape; a backup notice without a whole `created_at_ms` throws); `lastPassAtMs`: on the server's clock; `listing`: `{device_folder_id, device_folder_live, folders: [{category, category_folder_id, category_folder_live}]}`. An unknown category key, an id that is not a UUID, or a `lastPassAtMs` that is not a whole number throws. |
| `backupNoticeReason(type, data)` | The reason a `notifications` row gives (`"erase_request"`, ..., `"backup_deleted"`; `"unknown_removal"` for a removal whose reason this build does not know (Amendment 12b)), or `undefined` for a row that is not a backup notice. |
| `backupStopWords(reason, device, folder)` | Core's words for a stopped backup (the six lines of Amendment 12, final, and 12b's seventh, `unknown_removal`); an unknown reason throws. |
| `backupAgainAction()` | `"Back up again"`. |

### UniFFI

Counts are the `uniffi_beebeeb_uniffi_fn_*` and `uniffi_beebeeb_uniffi_checksum_*`
symbols the built library exports (`nm -D --defined-only` over the debug
`libbeebeeb_uniffi.so` of the base tree and of the head tree; these are the
symbols `uniffi-bindgen` writes into `beebeeb_uniffiFFI.h`; the base count
equals the v0.2.1 header count, 608), and `comm` over the sorted symbols.

- base (`v0.2.1`): 608 symbols
- head: 616 symbols
- **removed: 0**
- **added: 8** (4 functions, each with its checksum)

| Function | What |
| --- | --- |
| `backup_stop(notices, last_pass_at_ms, listing)` | `throws -> [BackupStopped]` (`category` key, `reason`); `notices` are `BackupNoticeRow { kind, data_json, created_at_ms }` (another kind is skipped, data that is not JSON reads as `null`); `listing` is `BackupStopListing { device_folder_id, device_folder_live, folders: [BackupStopFolder { category, category_folder_id, category_folder_live }] }`; an unknown category key or an id that is not a UUID is `InvalidInput` |
| `backup_notice_reason(kind, data_json)` | `String?`: the reason a row gives, or none for a row that is not a backup notice |
| `backup_stop_words(reason, device, folder)` | `throws -> String`: the words; an unknown reason is `InvalidInput` |
| `backup_again_action()` | `"Back up again"` |

The rebuild's clock (LD-0123) has no binding: `records_from_remote` had none in
v0.2.1 (spec §4.4 lists none); desktop and the CLI call it from Rust.

The committed `beebeeb-uniffi/bindings/` copy is regenerated by `build-ios.sh`
/ `build-android.sh` on the platform rung; this branch does not commit it.

### Rust (rustdoc JSON, private items included)

rustdoc JSON (`RUSTC_BOOTSTRAP=1 cargo rustdoc -p <crate> --lib -- -Z
unstable-options --output-format json --document-private-items`, pinned
1.96.0) of `v0.2.1` and of this branch, each item keyed by its path, ids
replaced by the paths they point to, docs, spans and child lists left out,
blanket and auto-trait impl members skipped:

| Crate | Added | Removed | Changed |
| --- | --- | --- | --- |
| `beebeeb_core` | 186 | 0 | 1 (private) |
| `beebeeb_types` | 84 | 0 | 0 |
| `beebeeb_uniffi` | 242 | 0 | 0 |
| `beebeeb_wasm` | 85 | 0 | 0 |
| `beebeeb_backup` | 0 | 0 | 0 |

The one changed item is the private helper `backup::rebuild::newest_copy`,
which takes the clock now; no public item changed. `records_from_remote` keeps
its v0.2.1 signature (it applies `RebuildClock::UNKNOWN`, the 10-minute
floor); the clock goes through the new `records_from_remote_with_clock`. The
instrument's self-test sees one removal, one retype and one addition, and 0/0/0
on identical input.

## Backup first-pass baseline and pass gate exports (LD-0121, Amendment 12c)

LD-0121, spec `2026-11-06-backup-from-source-design.md` Amendment 12c (Guus,
2026-11-07 20:45): the first pass's baseline and the pass gate when the
notices could not be read. Base: tag `v0.2.2` (`2d89adc1e2e3`). Additive only:
nothing in v0.2.2 is renamed, retyped or removed.

### WASM

Counted from source: the `js_name = …` names in `beebeeb-wasm/src` of the
v0.2.2 tree and of this branch, with `comm` over the sorted names. The
generated `.d.ts` is type-checked by CI's WASM JS surface job.

- base (`v0.2.2`): 149 names
- head: 152 names
- **removed: 0**
- **added: 3**

| Name | What |
| --- | --- |
| `backupFirstPassBaseline(setupAtMs?, legacyLastBackupMs?)` | The `lastPassAtMs` of a device with none under the new engine: the setup time, or an upgraded device's last old-engine backup; with both, the earlier; with neither, 0. A value that is not a whole number of milliseconds throws. |
| `backupPassGate(noticesFetchOk, notices, lastPassAtMs, listing)` | `{outcome: "run", stopped: [{category, reason}]}` (as `backupStop`), or `{outcome: "check_failed"}` when the notices could not be read: upload nothing, turn nothing off, keep `lastPassAtMs`, retry next pass. `notices` is not read when the fetch failed. |
| `backupCheckFailedWords()` | "Couldn't check — will retry." |

### UniFFI

Counted from source: the `#[uniffi::export]` functions in `beebeeb-uniffi/src`
of both trees, with `comm` over the sorted names.

- base (`v0.2.2`): 108 functions
- head: 111 functions
- **removed: 0**
- **added: 3**

| Function | What |
| --- | --- |
| `backup_first_pass_baseline(setup_at_ms, legacy_last_backup_ms)` | `Int64`, as `backupFirstPassBaseline` |
| `backup_pass_gate(notices_fetch_ok, notices, last_pass_at_ms, listing)` | `throws -> BackupPassGate` (`Run { stopped }` or `CheckFailed`); the listing parses as for `backup_stop` |
| `backup_check_failed_words()` | "Couldn't check — will retry." |

### Rust (rustdoc JSON, private items included)

The same instrument as v0.2.2's PRs (each item keyed by its path, ids replaced
by the paths they point to, docs, spans, child lists and blanket/auto-trait impl
members left out), `v0.2.2` against this branch, pinned 1.96.0:

| Crate | Added | Removed | Changed |
| --- | --- | --- | --- |
| `beebeeb_core` | 37 | 0 | 0 |
| `beebeeb_types` | 0 | 0 | 0 |
| `beebeeb_uniffi` | 73 | 0 | 0 |
| `beebeeb_wasm` | 33 | 0 | 0 |
| `beebeeb_backup` | 0 | 0 | 0 |

## Backup notice overlap and acknowledged ids exports (LD-0121, Amendment 12d, v0.2.5)

LD-0121, spec `2026-11-06-backup-from-source-design.md` Amendment 12d (server
#415 review finding 1; Guus 2026-11-08 03:16, "Go w recommended"): a backup
pass reads the removal notices with a 10-minute overlap and remembers the
notice ids it acted on. Ships as core v0.2.5. Measured against tag `v0.2.3`
(`df93011`); tag `v0.2.4` (`1d1a335`, the zip 8 → 9 bump) changes no file
under `src/` (`git diff --name-only v0.2.3 v0.2.4 -- '*/src/*'` is empty), so
every count below holds against v0.2.4 too. Additive only: nothing in v0.2.4
is renamed, retyped or removed; `backup_stop` / `backup_pass_gate`
(`backupStop` / `backupPassGate`) keep their behaviour and are documented as
superseded.

### WASM

Counted from source: the `js_name = …` names in `beebeeb-wasm/src` of the
v0.2.3 tree and of this branch, with `comm` over the sorted names. The
generated `.d.ts` is type-checked by CI's WASM JS surface job.

- base (`v0.2.3`): 152 names
- head: 156 names
- **removed: 0**
- **added: 4**

| Name | What |
| --- | --- |
| `backupNoticeOverlapMs()` | 600000: how far before `lastPassAtMs` a notice still counts (a notice's `created_at` is the start of the server transaction that wrote it, not its commit). |
| `backupNoticesSince(lastPassAtMs)` | The `since` to send to `GET /api/v1/notifications` (inclusive, integer ms): `lastPassAtMs` minus the overlap, never below 0. A value that is not a whole number of milliseconds throws. |
| `backupStopV2(notices, lastPassAtMs, acknowledged, listing)` | `{stopped: [{category, reason}], acknowledged: [id]}`. A notice (`{id, type, data, created_at_ms}`) counts when it is after `lastPassAtMs` minus the overlap and its `id` is not in `acknowledged`; `acknowledged` in the answer replaces the stored set. An `id` that is not a non-empty string is no id (never acknowledged). `acknowledged` may be `undefined`/`null`; a non-string entry throws. |
| `backupPassGateV2(noticesFetchOk, notices, lastPassAtMs, acknowledged, listing)` | `{outcome: "run", stopped, acknowledged}` (as `backupStopV2`), or `{outcome: "check_failed"}` when the notices could not be read: keep both `lastPassAtMs` and the acknowledged set. |

### UniFFI

Counted from source: the free functions directly under a `#[uniffi::export]`
in `beebeeb-uniffi/src` of both trees, with `comm` over the sorted names (this
scan counts v0.2.3 as 110; v0.2.3's own file said 111 by a scanner not in the
repo; the delta is the same either way).

- base (`v0.2.3`): 110 functions
- head: 114 functions
- **removed: 0**
- **added: 4**

| Function | What |
| --- | --- |
| `backup_notice_overlap_ms()` | `Int64`, as `backupNoticeOverlapMs` |
| `backup_notices_since(last_pass_at_ms)` | `Int64`, as `backupNoticesSince` |
| `backup_stop_v2(notices, last_pass_at_ms, acknowledged, listing)` | `throws -> BackupStopOutcome` (`stopped`, `acknowledged`); rows are `BackupNoticeRowV2` (`id: String?`, `kind`, `data_json`, `created_at_ms`); the listing parses as for `backup_stop` |
| `backup_pass_gate_v2(notices_fetch_ok, notices, last_pass_at_ms, acknowledged, listing)` | `throws -> BackupPassGateV2` (`Run { stopped, acknowledged }` or `CheckFailed`) |

The committed Kotlin bindings under `bindings/` are not regenerated here (they
do not carry the v0.2.2/v0.2.3 backup functions either).

### Rust (rustdoc JSON, private items included)

Each item keyed by its path, ids replaced by the paths they point to, docs,
spans, child lists and blanket/auto-trait impl members left out; `v0.2.3`
against this branch, rustc 1.96.0 (`RUSTC_BOOTSTRAP=1`, separate target dirs
per tree). Seen red: with the inputs swapped it reports `beebeeb_core` 43
removed, and a head with `backup_stop`'s `last_pass_at_ms` retyped to `u64`
reports 1 changed.

| Crate | Added | Removed | Changed |
| --- | --- | --- | --- |
| `beebeeb_core` | 43 | 0 | 0 |
| `beebeeb_types` | 0 | 0 | 0 |
| `beebeeb_uniffi` | 124 | 0 | 0 |
| `beebeeb_wasm` | 18 | 0 | 0 |
| `beebeeb_backup` | 0 | 0 | 0 |

## Native share calls on the share flow (0.3.0)

The native share calls no longer build share bodies: core's `share_flow` builds every request, which
`beebeeb_api::FlowRequest` sends as built. 0 callers on web, mobile, desktop and cli `main` used the
changed exports.

### UniFFI

| Export | Before | Now |
| --- | --- | --- |
| `ShareServiceHandle.create_link` | `(file_id, wrapped_file_key, expires_in_hours: Option<i64>, passphrase: Option<String>) -> ShareData` | `(app_url, file_id, expires_in_hours: Option<u32>, max_opens: Option<u32>, passphrase: Option<SecretString>) -> CreatedLinkData`: Rust wraps the file key and seals the owner copies; no expiry unless one is given |
| `CreatedLinkData` | none | `{share_id, link: SecretString, display: SecretString}`: `link` carries the link key after `#key=`; `display`, the part before `#`, still names the link's token |
| `ShareData` | `{id, file_id, expires_at}` | removed |
| `ServiceError::ShareRefused { code }`, `ServiceErrorKind::ShareRefused` | none | a share the flow or the server refused; `code` is the share flow's code |

### Rust

| Item | Before | Now |
| --- | --- | --- |
| `beebeeb_api::FlowRequest` | none | `new(HttpRequest)`, `build(RequestBuilder)` (a step-up's confirm token goes in through the builder's `with_confirmation`), `max_response_bytes()`, `answer(Answer) -> HttpResponse` (any status) |
| `beebeeb_api::routes::invites` | `Create`, `create`, `Approve`, `approve`, `ActionResponse` | removed: `share_flow::member` builds the invite and the approval |
| `beebeeb_api::routes::shares` | `Create`, `create`, `CreateLink`, `create_link`; `Share.token` | removed: `share_flow::link` builds the link; no answer that `Share` reads carries a token |
| `beebeeb_api::routes::folder_links` | `Create`, `create` | removed: `share_flow::folder` builds the folder link |
| `Client::create_share_link` | `(file_id, wrapped_file_key, expires_in_hours, passphrase) -> shares::Share` | `(app_url, file_id, &LinkOptions) -> CreatedLink` |
| `Client::create_invite` | `(invites::Create) -> invites::Invite` | `(file_id, email, PeerKeyExpectation) -> InviteOutcome` |
| `Client::create_trusted_invite` | `(store, invites::Create, contact_id, presented_public_key, observed_at) -> invites::Invite` | `(store, file_id, email, contact_id, presented_public_key, observed_at) -> InviteOutcome`: sealed only for `presented_public_key` |
| `Client::approve_invite` | `(id, encrypted_file_key) -> ()` | `(invite_id, file_id, recipient_public_key_b64, PeerKeyExpectation) -> [u8; 32]`, the key sealed for |
| `Client::create_folder_link` | `(folder_links::Create) -> folder_links::Link` | `(FolderLinkInput, record_custody_seen) -> CreatedFolderLink` |
| `ShareServiceError` | `Client`, `Store`, `ContactKeyChanged` | adds `Flow(ShareFlowError)`, `KeyUnavailable` (a foreign item id) and `CustodyNotRecorded` |
| `beebeeb_client::shares::share_flow` | none | re-export of `beebeeb_core::share_flow` |

### Share refusals and link limits (0.3.0)

| Item | Before | Now |
| --- | --- | --- |
| `ShareFlowError::Forbidden { code: String }` | none | a 403 refusal: `code` is the server's code (`code`, else `error`: `sharing_paused`, `email_unverified`, `billing_read_only`, ...), or `forbidden` when the body names none (the account-frozen 403 sends a sentence). `code()` is `forbidden` |
| `ShareFlowError::from_status` | a 401 or 403 without a share refusal code was `Unauthorized` | a 401 is `Unauthorized`, a 403 is `Forbidden { code }` |
| `ShareFlowError::host_code` | none | the code a host shows: `Forbidden`'s `code`, else `code()` |
| `share_flow::link::CreateLink::on_response` (file links and bundles) | a 409 without a string `code` from the share refusals got a fresh token and was sent again | only the server's token collision (`error` `share token already exists — regenerate and retry`, or `token_taken`) is sent again, once; every other 409 is the flow's error, a refusal in `error` included |
| `share_flow::link::MAX_EXPIRES_IN_HOURS`, `MAX_OPENS` | none | `8760` (one year) and `i32::MAX`; `LinkOptions` (file links and bundles) and `FolderLinkInput` past them are `InvalidInput("expires in hours")` / `InvalidInput("max opens")` before any request |
| UniFFI `ServiceError` of `ShareServiceHandle.create_link` | a 403 was `Authentication` | `ShareRefused { code }` with the server's code |
| UniFFI `ShareFlowFfiError::Flow { code }`, the WASM share flows' `JsError` message | `ShareFlowError::code()` (`unauthorized` for a 403) | `ShareFlowError::host_code()` (a 403's own code) |

## Account step-up, server errors, contact keys and the store (0.3.0)

Rust only, and none of it was in a release: `beebeeb-api`, `beebeeb-client`, `beebeeb-store` and
`contact_keys` are new in 0.3.0, and `ServerError`'s two methods are additions. "Before" is this
release's earlier development state.

| Item | Before | Now |
| --- | --- | --- |
| `beebeeb_client::auth::AuthError::PasswordNotConfirmed` | none | the step-up did not confirm the password: a wrong password, or a 401 at `confirm-opaque-start` or `confirm-opaque-finish` while `GET /auth/me` still answers (a gone session is the 401 itself, reported expired once) |
| `ServerError::parse_coded_body(status, body)` | none | decodes a body whose code is in `code` and text in `error` (the account-delete routes); without a string `code` it decodes as `parse_body` |
| `ServerError::with_retry_after_header(value)` | none | takes the delay from a `Retry-After` header when the body names none |
| `beebeeb_api::Endpoint::is_step_up` | none | true for `confirm-opaque-start` and `confirm-opaque-finish`: their 401 emits no `SessionExpired` |
| `routes::account::TotpCode.code`, `routes::account::TotpSetupRequest.code` | `String`, `Option<String>` | `Zeroizing<String>`, `Option<Zeroizing<String>>` |
| `routes::auth::CodeRequest.code`, `routes::auth::TwoFactorRequest.code` and `.partial_token` | `String` | `Zeroizing<String>` |
| `proposed::EmailCodeSubmit.code` | `String` | `Zeroizing<String>` |
| `proposed::RecoveryComplete.email_verification_code` | `Option<String>` | `Option<Zeroizing<String>>` |
| `proposed::AuthenticatorChange.code` and `.secret` | `Option<String>` | `Option<Zeroizing<String>>` |
| `routes::onboarding::EmailVerify.code` | `String` | `Zeroizing<String>` |
| `beebeeb_core::contact_keys::{safety_number, key_fingerprint, check_pin, PinCheck, SAFETY_NUMBER_ROUNDS}` and their `beebeeb_client::contacts` re-export (`PinCheck`, `check_pin`, `key_fingerprint`, `safety_number`) | public | removed; `contact_keys` keeps `normalize_email`. The safety number and fingerprint are `share_flow::safety`'s. The crate-private labels `KEY_FINGERPRINT_DOMAIN` and `SAFETY_NUMBER_DOMAIN` went with them |
| `beebeeb_store::StoreError::Database` | `rusqlite::Error` of `rusqlite` 0.32 | `rusqlite::Error` of `rusqlite` 0.41 (`libsqlite3-sys` 0.39) |

## Sign-in, account, passkey and share flow exports (0.2.7 and 0.2.8)

The sans-IO flows of `beebeeb_core` (`auth_flow`, `account_flows`, `signup_flow`, `recovery_flow`,
`passkey`, `share_flow`) and their bindings, as released in 0.2.8, newest first. They are separate from
the native service handles above: a flow returns an HTTP request and takes the answer, and the platform
owns the transport. The committed Swift and Kotlin bindings include them.

### Review hardening before v0.2.8: changed signatures, removed 0, added 0 exports

The full list is CHANGELOG `[0.2.8]` → "Changed". Exports whose signature changed:

- **WASM:** `passkeyParseRegistrationStart(answerJson, expectedRpId, allowLocalhost)`,
  `passkeyParseAssertionStart(answerJson, expectedRpId, allowLocalhost)`,
  `shareRebuildLink(appUrl, masterKey, ownerWrappedKey?, ownerWrappedToken?, wrappedFileKey)` (required), `shareRebuildBundleLink(appUrl, masterKey, ownerWrappedKey?, ownerWrappedToken?)`,
  `AccountFlow.changePassword(current, newPassword, recoveryCheckB64, x25519PublicB64, onboardingStatus,
  onboardingBody, breachCheck?)`; `new AuthStepUp(password, purpose?, cliCode?)` refuses a `cliCode` with another
  purpose. WASM keeps raw key bytes (its convention).
- **UniFFI:** `passkey_parse_registration_start` / `passkey_parse_assertion_start` (+ `expected_rp_id`,
  `allow_localhost`); `AccountFlowHandle::change_password` (+ `onboarding_status`, `onboarding_body`,
  `breach_check: Option<BreachCheckHandle>`); `StepUpFlow::new` refuses a `cli_code` with another purpose; keys as
  handles: `SignupCreatedFfi.master_key`, `RecoveredFfi::SignedIn.master_key`, `DeviceRequestEventFfi::Approved.master_key`,
  `ApprovalFlow::approve`, `MemberInviteFlow::new`, `share_approve_file_invite_request`, `share_open_member_file_key`,
  `CreateLinkFlow::new` / `bundle` (`BundleItemFfi.file_key`), `share_rebuild_link` (+ required `wrapped_file_key`), `share_rebuild_bundle_link`,
  `share_open_link_file_key`, `FolderShareFlow::new` / `link`, `CreateRequestFlow`, `share_rebuild_folder_link` and
  the file-request rebuild take or return `MasterKeyHandle` / `FileKeyHandle`.

### Share flows (0.2.8)

Desktop v2 B05b (Guus: every crypto and account flow lives in core). Person shares of a file and double-encrypted
file links move into core as `beebeeb_core::share_flow`, byte-identical to web (web's `share-wrap-kat` vectors and
the `x25519_share_key_exchange` vector are pinned in `share_flow::tests`). Measured against `main` at `e3eeb8b`.
Additive only, except `auth_flow::Method` gains `Delete` (a host that matches it exhaustively adds one arm).

#### WASM

Counted from source (unique `js_name = …` under `beebeeb-wasm/src`): base 187, head 193.

- **removed: 0**
- **added: 6**

| Name | What |
| --- | --- |
| `shareWrapKey(wrapKey, key)` / `shareUnwrapKey(wrapKey, wrapped)` | Web's `wrapKeyForShare` / `unwrapKeyFromShare`: `nonce(12) \|\| ct`, no AAD. |
| `ShareMemberInvite(itemId, isFolder, email, expectedPeerFingerprint, masterKey, fileKey)` (`expectedPeerFingerprint` required: 32 bytes, or empty = not compared) | `start()`, `onResponse(...)` → `{kind: "send"}` / `"shared"` / `"invited"` / `"awaiting_approval"` / `"peer_key_changed"` (B05e: the server key differs from `expectedPeerFingerprint`, nothing sealed; "share anyway" re-approves the carried key with the fingerprint of those bytes); `shared` and `peer_key_changed` carry `recipientPublicKey` (hex), the key sealed to / offered. A folder throws `invalid_input` (use `ShareFolderInvite`). |
| `shareApproveFileInviteRequest(inviteId, fileId, recipientPublicKeyB64, masterKey, fileKey, expectedPeerFingerprint)` (B05e) | `{request, recipientPublicKey}` (hex: the exact key sealed to). `expectedPeerFingerprint` required (32 bytes, or empty = not compared). Throws `peer_key_changed` on a different key. |
| `ShareFolderInvite(folderId, email, expectedPeerFingerprint, sharedFoldersWrite, custodySeen, custodyUnreadable, masterKey)` (B05c, B05e) | `start()` / `onResponse(...)` → `{kind: "send", request, markCustodySeen}` (persist the id BEFORE sending) / `"shared"` / `"invited"` / `"awaiting_approval"` / `"peer_key_changed"`. Throws `folder_key_unverified`, `folder_keys_unavailable`, `folder_needs_upgrade`, `folder_too_large`. |
| `ShareFolderInvite.link(folderId, appUrl, accessLevel, label?, expiresInHours?, capBytes?, maxOpens?, passphrase?, custodySeen, custodyUnreadable, masterKey)` (B05c) | Web's `createFolderLinkWithKeys`: same steps, ends `{kind: "link_created", shareId, link, display, accessLevel, passphraseProtected, keyVersion}`. |
| `shareSafetyNumber(masterKey, ownUserId, peerUserId, peerPublicKey)` (B05e) | `{digits, peerFingerprint}`: the 60-digit safety number (Signal numeric fingerprint v1, 5200 SHA-512 rounds per party, lower user id first) and SHA-256 of the peer key as hex. The own key is derived from the master key in core; `peerPublicKey` is the raw 32-byte key the share was sealed to (`recipientPublicKey` of the invite outcome). User ids are canonical lowercase UUIDs and must differ; keys with bit 255 set or of small order throw `invalid_input`. UniFFI: `share_safety_number(master_key, ...)` → `SafetyNumberFfi`. Vectors: `test-vectors/safety_number.json`. |
| `ShareCreateRequest(appUrl, title, description?, targetFolderId?, maxFiles?, maxTotalBytes?, expiresInSecs?, masterKey)` (B05c) | A file request (web `pages/file-request.tsx`): `start()`, `onResponse(...)` → `{id, link, display}`; `link` is `/r/{token}#{b64url(R_pub)}`. |
| `shareRebuildFolderLink(appUrl, masterKey, shareId, ownerWrappedKey?, ownerWrappedToken?, wrappedFolderKey?, passphraseProtected)` (B05c) | Web `rebuildFolderLinkUrl`: the owner's folder link, or `undefined`. UniFFI: `share_rebuild_folder_link`. |
| `fileRequestRebuildLink(appUrl, masterKey, token?, wrappedPrivateKey?, wrapNonce?)` (B05c) | Web `handleCopyExisting`: the request's link again, or `undefined`. |
| `shareCreateBundle(appUrl, fileIds, positions, fileKeys, masterKey, expiresInHours?, maxOpens?, passphrase?)` (B05c) | A `ShareCreateLink` over an ordered set of files (web's bundle branch); `fileKeys` is the 32-byte keys concatenated. |
| `ShareCreateLink(appUrl, fileId, masterKey, fileKey, expiresInHours?, maxOpens?, passphrase?)` | `start()`, `onResponse(...)` → `{kind: "send"}` (one retry on an untyped 409) / `{kind: "created", shareId, link, display}`. |
| `shareRebuildLink(appUrl, masterKey, ownerWrappedKey?, ownerWrappedToken?, wrappedFileKey)` (required), `shareRebuildBundleLink(appUrl, masterKey, ownerWrappedKey?, ownerWrappedToken?)` | Web's `buildShareLink`: the owner's link, or `undefined`. |
| `shareOpenMemberFileKey(masterKey, ownerPublicKey, fileId, sealed)` | The recipient side of a person share. |

#### UniFFI

- **removed: 0**
- **added:** objects `MemberInviteFlow`, `CreateLinkFlow`; enums `InviteStepFfi`, `LinkStepFfi`; error
  `ShareFlowFfiError::Flow { code }`; functions `share_approve_file_invite_request`, `share_open_member_file_key`,
  `share_rebuild_link`, `share_open_link_file_key`, `share_revoke_request`. Requests reuse `AuthHttpRequest`.
- **added (B05c):** object `FolderShareFlow` (constructor `new` = a folder invite, `link` = a folder link), enum
  `FolderStepFfi` (`Send` carries `mark_custody_seen`; `LinkCreated` carries `link` with `#key=` and `display`).
- **changed (B05e):** `share_safety_number(master_key, own_user_id, peer_user_id, peer_public_key)`; `MemberInviteFlow::new`, `FolderShareFlow::new` and `share_approve_file_invite_request` take a required `peer_key: PeerKeyExpectationFfi` (`Compared { fingerprint }` / `NotCompared`), and the approve function returns `SealedApprovalFfi { request, recipient_public_key }`; `InviteStepFfi` / `FolderStepFfi` gain `PeerKeyChanged { invite_id, recipient_public_key }` and `recipient_public_key` on `Shared` / `AwaitingApproval`.
- **added (B05c):** object `CreateRequestFlow`, record `CreatedRequestFfi`, functions `file_request_rebuild_link`,
  `file_request_close_request`; `CreateLinkFlow.bundle` constructor with record `BundleItemFfi`.

#### Rust

New module `beebeeb_core::share_flow` (`member`, `link`; B05c: `folder` with `folder::link`, `folder_keys`, `request`, `bundle`); `auth_flow::Method::Delete`
and (B05c) `Method::Put`, with their `account_flows` arms. `ShareFlowError::FolderInviteUnsupported` is gone (B05c):
four folder codes replace it. B05e: `share_flow::safety` (`safety_number(master, …)`, `key_fingerprint`), `share_flow::access::set_member_access_request(id, MemberPermission)`, `ShareFlowError::PeerKeyChanged` (`peer_key_changed`), `InviteOutcome::PeerKeyChanged` and the sealed `recipient_public_key` on `Shared` / `AwaitingApproval`, a required `PeerKeyExpectation` on `MemberInvite::start` / `FolderInviteInput.peer_key` / `approve_request` (the only public member seal; `seal_file_key_for_member` is `pub(crate)`) (which now returns `SealedApproval`), and `Method::Patch` with its `account_flows` arm.

### Account, signup and recovery flows (0.2.8)

Desktop v2 B10b: server PR #422's routes wired into `account_flows` and `auth_flow`, and the bindings for B11's
`signup_flow` / `recovery_flow` (crypto rule 0). Measured against `main` at `e3eeb8b`.

**Not additive: 2 signatures change** (the server now asks for more). Both in Rust, UniFFI and WASM:
- `AccountFlow::delete_account(password)` → `delete_account(password, code?)`: it now calls
  `POST /auth/account/delete-request` (the server mails a link; nothing is scheduled), outcome `deletion_requested`.
- `AccountFlow::set_activity_logging(on)` → `set_activity_logging(on, password?)`: turning it off steps up inside.

#### WASM

- **removed: 0; changed: 2** (`AccountFlow.deleteAccount`, `AccountFlow.setActivityLogging`)
- **added:** classes `SignupFlow`, `PhraseRecovery`; functions `signupPolicyRequest`, `recoveryUnknownWordPositions`;
  methods `AccountFlow.regenerateBackupCodes`, `deleteConfirm`, `deleteCancel`; `AuthApproval.deny`, `onDenyResponse`.
- Outcome kinds added: `deletion_requested` (`link_expires_at`), `deletion_cancelled` (`not_restored`);
  `deletion_scheduled` gains `cancel_until`. Error codes added: `second_factor_required`, `link_invalid`,
  `confirmation_required`.

#### UniFFI

- **removed: 0; changed: 2** (`AccountFlowHandle.delete_account`, `set_activity_logging`; record
  `AccountFlowOutcome` gains `cancel_until`, `link_expires_at`, `not_restored`)
- **added:** objects `SignupFlowHandle`, `PhraseRecoveryHandle`; record `SignupCreatedFfi`; enum `RecoveredFfi`;
  error `SignupFlowFfiError::Flow { code, retry_after_secs }`; functions `signup_policy_request`,
  `recovery_unknown_word_positions`; methods `AccountFlowHandle.regenerate_backup_codes`, `delete_confirm`,
  `delete_cancel`; `ApprovalFlow.deny`, `on_deny_response`.

### Sign-in, step-up and device approval flows (0.2.8)

Desktop v2 B10 (`docs/superpowers/specs/2026-11-08-desktop-v2-design.md`, crypto review rule 0): the sign-in,
step-up and device-approval flows move into core. Additive only: nothing is renamed, retyped or removed. Measured
against `main` at `124389a` (v0.2.7).

#### WASM

- **removed: 0**
- **added: 4 classes** (`js_name` count +4)

| Name | What |
| --- | --- |
| `AuthSignIn(email, password)` | `start()`, `onResponse(status, body, retryAfter?)` → `{kind: "send", request}` / `{kind: "signed_in", sessionToken}` / `{kind: "second_factor"}`; `verifyRequest(code)`, `onVerifyResponse(...)` → session token. |
| `AuthStepUp(password, purpose?, cliCode?)` | `start()`, `onResponse(...)` → `{kind: "send"}` / `{kind: "confirmed"}`; `attachConfirmToken(path, body)` → the consuming request with `confirmToken`. |
| `AuthDeviceRequest()` | `initFrame(deviceName?, client, version, os)`, `onFrame(text)` → `{kind: "waiting", userCode, verificationUri, expiresIn}` / `{kind: "approved", sessionToken, masterKey}`. |
| `AuthApproval(code)` | `start()`, `onLookupResponse(...)` → facts, `codeMatches(typed)`, `approve(typed, password, masterKey)`, `onResponse(...)` → `{kind: "send"}` / `{kind: "approved"}`. |

Errors throw `JsError(code)`: `invalid_credentials`, `wrong_code`, `rate_limited:<secs>`, `account_deleted`,
`opaque_unavailable`, `request_not_found`, `already_handled`, `expired`, `denied`, `keys_did_not_arrive`, …

#### UniFFI

- **removed: 0**
- **added:** objects `SignInFlow`, `StepUpFlow`, `DeviceRequestFlow`, `ApprovalFlow`; records `AuthHttpRequest`,
  `AuthHttpResponse`, `RequesterFactsFfi`; enums `SignInStepFfi`, `StepUpStepFfi`, `DeviceRequestEventFfi`,
  `ApproveStepFfi`; error `AuthFlowFfiError::Flow { code, retry_after_secs }`. Same shapes as WASM.

### Passkey vault (0.2.8)

B15 (desktop v2, passkeys; Guus 2026-11-08: the logic in core, only the platform call in each client). Measured
against `124389a` (v0.2.7). Additive only: nothing is renamed, retyped or removed.

#### WASM

Counted from source: the unique `js_name = …` names under `beebeeb-wasm/src` (`grep -o | sort -u | wc -l`).

- base (`124389a`): 156 names
- head: 162 names
- **removed: 0**
- **added: 6**

| Name | What |
| --- | --- |
| `passkeyPrfEvalInput()` | The 32-byte `prf.eval.first` web passes (`beebeeb.io/vault-wrap-key/v1`, zero-padded). |
| `passkeyWrapVaultKey(prfOutput, masterKey)` | The escrow blob `nonce(12) || ct(32) || tag(16)`; web's `encryptVaultBlob` format. |
| `passkeyUnwrapVaultKey(prfOutput, blob)` | The 32-byte vault key; throws on a wrong PRF output, a changed byte or a blob that is not 60 bytes. |
| `passkeyParseRegistrationStart(answerJson)` | `register-start`'s answer as `RegistrationStart` JSON. |
| `passkeyParseAssertionStart(answerJson)` | `login-start`'s answer as `AssertionStart` JSON. |
| `passkeyEscrowBody(credentialId, blob)` | The `vault-key-escrow` POST body. |

Web keeps its TS (`src/lib/passkey-vault.ts`) until a later web task switches; the vectors prove parity.

#### UniFFI

- **removed: 0**
- **added: 10** free functions (`passkey_prf_eval_input`, `passkey_hmac_secret_salt`, `passkey_wrap_vault_key`,
  `passkey_unwrap_vault_key` → `MasterKeyHandle` (no raw key crosses), `passkey_parse_registration_start`,
  `passkey_registration_finish_body`, `passkey_escrow_body`, `passkey_parse_assertion_start`,
  `passkey_assertion_finish_body`, `passkey_parse_escrow`).

#### Rust

New module `beebeeb_core::passkey` (`ceremony`, `flow`); no existing item changed.

## Archive exports (0.3.0)

List, preview and extract zip, tar, tgz and gz (spec `2026-11-07-core-archives-design.md` §5, §8, §9).
Every rule is core's (`beebeeb_core::archives`); the bindings convert. The old reader
(`beebeeb_core::archive`) and its three exports per binding are removed (a break; 0 callers in the
web, desktop, CLI and mobile app sources): see "Removed" below.

### WASM

Counts are the `export function` / `export class` names in the generated `beebeeb_wasm.d.ts`
(`wasm-pack build beebeeb-wasm --dev --no-opt`); this branch changes no other WASM source, so the base is
the head minus the names below.

- base: 177 names
- head: 183 names
- **removed: 0**
- **added: 6**

| Name | What |
| --- | --- |
| `new WasmArchiveSession(len, platform)` | A push session for an archive of `len` (bigint) bytes on `"native"`, `"browser"` or `"mobile_app"`. `step()` → `{kind: "need_bytes", start, end}` (answer with `supply(offset, bytes)`, then step again), `{kind: "listed"}`, `{kind: "refused", refusal, format, text}` or `{kind: "io", message}`. `releaseBefore(offset)`; `listing()` → `{format, entries, totals, protection, uses_zipcrypto, complete}`; `checkPassword(index, password)` → `need_bytes` / `accepted` / `wrong` / `damaged` (the entry's headers are damaged; reading it reports `corrupt`) / `not_needed` / `io`; `preview(input)` and `previewWithPlan(input, plan)` → the screen model; `plan(request)` → a `WasmExtractionPlan` or `{kind: "refused", refusal, text}`; `startExtraction(identity, plan, password?)` → a `WasmArchiveExtraction` (the session moves into it; later calls throw); `openEntry(index, password?)` → `need_bytes` / `{kind: "bytes", bytes}` (after its check passed) / `corrupt` / `wrong` / `skipped` / `too_large` / `io`. |
| `WasmExtractionPlan` | Core's plan, opaque, so the run uses it unedited: `kind` (`"planned"`), `view()` → `{target, nodes, skipped, renamed, totals, notices}`. |
| `WasmArchiveExtraction` | `step()` → `need_bytes`, `need_password`, `create_folder`, `file_begin`, `file_data` (`bytes`: a `Uint8Array`, not yet verified), `file_end` (verified: upload it), `file_skipped` (drop what was staged; a protected file whose password passed its check byte but failed its CRC is skipped once, asked for again with `need_password` and begun again under the same `node`), `progress` (with its `text`), `waiting` or `finished` (outcome, reason, counts, skipped, renamed, `text`). Reports: `supply`, `releaseBefore`, `folderCreated(node, id)`, `folderNameTaken(node)`, `uploadFinished(node, ok)`, `identitySeen({file_id, object_version_id})`, `runFailed(reason)`, `supplyPassword(password)` (taken only right after `need_password`; any other time it is dropped), `cancel()`; `preview(input)` while it runs and after. |
| `archiveText(key, args)` | Core's words: `{key, text, args}`; an unknown key throws. |
| `archiveCountLabel(n)` | `1,234`. |
| `archiveSizeLabel(bytes)` | `3.4 MB` (core's compact formatter, one decimal). |

Every 64-bit number crosses as a `bigint` and an absent field is `null`. A password becomes core's
zeroizing `ArchivePassword` as it enters. An unknown platform, word, destination, backup position,
selection or fail reason throws. `beebeeb-wasm/js-tests/archives.test.cjs` runs every fixture, word,
count and size of `test-vectors/archives_v1.json` through the module.

### UniFFI

Counts are the `uniffi_beebeeb_uniffi_fn_*` and `uniffi_beebeeb_uniffi_checksum_*` symbols in the
regenerated `beebeeb_uniffiFFI.h`, base (this branch's merge base header) against head, `comm` over
the sorted symbols.

- base: 974 symbols
- head: 982 symbols
- **removed: 0**
- **added: 8** (4 functions, each with its checksum)

| Function | What |
| --- | --- |
| `archive_text(key, args: [ArchiveTextArg])` | `throws -> ArchiveText` (`key`, `text`, `args`); an unknown key is `InvalidInput` |
| `archive_count_label(n)` / `archive_size_label(bytes)` | the count and size as the words show them |
| `archive_list(bytes, platform)` | `throws -> ArchiveListResult` (`listed { listing }` or `refused { refusal, text }`) for an archive already in memory (the vectors, a small attachment); a large archive is listed by range reads in the archive service |

Records and enums mirror core field for field: `ArchivePreviewModel` (`ArchivePreviewState`,
`ArchivePreviewRow`, `ArchivePreviewAction`, `ArchiveActionKind`), `ArchiveListing` (`ArchiveEntry`,
`ArchiveEntryKind`, `ArchiveCipher`, `ArchiveTime`, `ArchiveSkipReason`, `ArchiveTotals`,
`ArchiveProtection`, `ArchiveFormat`), `ArchiveRefusal`, `ExtractProgress`, `ExtractSummary`
(`ExtractOutcome`, `ExtractFailReason`, `ArchiveSkippedEntry`, `ArchiveRenamedEntry`) and `ArchiveText`.
#### The archive service (`ArchiveServiceHandle`)

`NativeClientHandle.archives(downloads, uploads, temp_root, platform)` → `ArchiveServiceHandle` over
`beebeeb_client::archives::ArchiveService` (`platform`: `"mobile_app"` on the phone). It needs the
application runtime (`unavailable` on the lightweight one) and one live service per `temp_root` (a second
is refused until the first is dropped). The service owns `temp_root`: at start it cancels the queued
uploads an earlier process left there and deletes their staged files; other files stay. The archive is
read by range (`DownloadService::read_range`, v1 and v2 through core's `RangeOpener`); each file is staged
0600 as `archive-<instance>-<run>-<node>.bbtmp`, enqueued on the upload queue only after its own check
passed, and deleted when its upload ends, the entry is skipped, or the run stops, fails or its service is
dropped (a dropped service stops its runs).

| Method | What |
| --- | --- |
| `open(file: DownloadData, name, parent_id)` | `throws ArchiveError -> u64`: starts listing; the listing arrives as a `model` event |
| `preview(archive_id, folder, selection)` | `throws -> ArchivePreviewModel` for one folder of the archive |
| `extract(archive_id, ArchiveExtractOptions, password?)` | `throws -> u64` (the extraction); `ArchiveError.Refused { reason, text }` when the planner refuses (nothing written); uploads follow the device's upload settings |
| `supply_password(extraction_id, password)` | answers a `model` event in `needs_password` (dropped if the run is not asking) |
| `open_entry(archive_id, index, password?)` | `throws -> bytes` after the entry's own check passed, up to the platform's in-memory budget |
| `cancel(extraction_id)` / `close(archive_id)` | stop a run (finished uploads stay) / close the archive and wipe its passwords |
| `observe()` | `ArchiveEventStreamHandle.next(timeout_ms) -> ArchiveEventData?` (`model`, `read_failed`, `finished`) |

New records and enums: `ArchiveExtractOptions` (`selection: [String]?`, `destination`,
`device_free_bytes`), `ArchiveDestination` (`next_to_archive`, `folder { parent_id }`),
`ArchiveEventData`, `ArchiveError`. A password crosses as a `SecretString` and becomes an
`ArchivePassword` at once.

### Removed: the old archive reader

The extension-based `beebeeb_core::archive` (`list_tar_entries`, `decompress_gzip`, `list_archive`) is
deleted with its exports. `git grep -c -E 'list_archive|decompress_gzip|listArchive|decompressGzip|list_tar_entries|listTarEntries|ArchiveEntryDto'`
on each client's `origin/main` (2026-11-08): web `src` 0, desktop 0, cli 0, mobile `src` 0 and its
hand-written native modules 0 (its 71 hits are the vendored generated binding copies, replaced when it
pins this release).

- WASM (`export function` / `export class` names in `beebeeb_wasm.d.ts`, base `52804a2` against
  head): 182 → 179, **removed: 3** (`list_tar_entries`, `decompress_gzip`, `list_archive`), added: 0.
- UniFFI (`fn` / `checksum` symbols in `beebeeb_uniffiFFI.h`, same base): 982 → 1000, **removed: 6**
  (`list_tar_entries`, `decompress_gzip`, `list_archive`, each with its checksum; the
  `ArchiveEntryDto` record goes with them), **added: 24** (the archive service: `nativeclienthandle_archives`,
  eight `archiveservicehandle_*` methods and `archiveeventstreamhandle_next`, each with its checksum,
  plus the two objects' `clone` / `free`).
