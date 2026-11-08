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
| `safetyNumber(emailA, publicKeyA, emailB, publicKeyB)`, `normalizeEmail(raw)` | none | core's safety number and email normalisation; web never trims an email itself |
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
| `safety_number(email_a, public_key_a, email_b, public_key_b)`, `normalize_email(raw)` | none | core's safety number and email normalisation |

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
| `WasmArchiveExtraction` | `step()` → `need_bytes`, `need_password`, `create_folder`, `file_begin`, `file_data` (`bytes`: a `Uint8Array`, not yet verified), `file_end` (verified: upload it), `file_skipped` (drop what was staged; a protected file whose password passed its check byte but failed its CRC is skipped once, asked for again with `need_password` and begun again under the same `node`), `progress` (with its `text`), `waiting` or `finished` (outcome, reason, counts, skipped, renamed, `text`). Reports: `supply`, `releaseBefore`, `folderCreated(node, id)`, `folderNameTaken(node)`, `uploadFinished(node, ok)`, `identitySeen({file_id, object_version_id})`, `runFailed(reason)`, `supplyPassword(password)`, `cancel()`; `preview(input)` while it runs and after. |
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
`beebeeb_client::archives::ArchiveService` (`platform`: `"mobile_app"` on the phone; the service owns
`temp_root` and deletes what an earlier process left there). The archive is read by range
(`DownloadService::read_range`, v1 and v2 through core's `RangeOpener`); each verified file is staged
0600 in `temp_root`, enqueued on the upload queue only after its own check passed, and deleted when its
upload ends, the entry is skipped or the run stops or fails.

| Method | What |
| --- | --- |
| `open(file: DownloadData, name, parent_id)` | `throws ArchiveError -> u64`: starts listing; the listing arrives as a `model` event |
| `preview(archive_id, folder, selection)` | `throws -> ArchivePreviewModel` for one folder of the archive |
| `extract(archive_id, ArchiveExtractOptions, password?)` | `throws -> u64` (the extraction); `ArchiveError.Refused { reason, text }` when the planner refuses (nothing written); uploads follow the device's upload settings |
| `supply_password(extraction_id, password)` | answers a `model` event in `needs_password` |
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
