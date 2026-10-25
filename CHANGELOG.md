# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Chunk format v2 (task 1908): file-content frames authenticate their position as AES-GCM
  associated data — `"beebeeb/chunk/v2" || len(file_id) || file_id || version_id(12) ||
  chunk_index || is_last` (STREAM construction) — and are sealed under a dedicated chunk subkey
  `HKDF-SHA256(file_key, "beebeeb/chunk/v2/key")` that no other blob type uses. `version_id` is
  the random nonce of the upload's frame 0, so frames of two uploads (versions) of one file id
  cannot be mixed. Previously (v1) frames carried no associated data, so a malicious server could
  reorder, duplicate, drop, truncate or splice chunks undetected. Same frame layout and sizes;
  the server is unaffected.
- Every file-content reader now REQUIRES an `ExpectedChunkFormat` taken from the file's
  encrypted metadata (`encrypt::decrypt_name_metadata[_with_key]`): `V2` accepts only v2 frames,
  so a server can no longer pass a same-key no-AAD blob (encrypted name, thumbnail) off as a
  one-frame v1 file; `Unrecorded` (metadata without a format: files from before the switch) lets
  frame 0 decide. Readers reject out-of-order frames, frames from another upload, frames after
  the last chunk, and fail at `finish()`/EOF when a v2 file ended early. A zero-frame body is now
  an error (it used to decrypt to an empty file). Uploads record the format with
  `encrypt::encrypt_name_with_chunk_format` (`"chunk_format": 2`); `encrypt_name` output is
  unchanged.
- Read-only rollout phase: `chunk_stream::WRITE_FORMAT` stays `V1Legacy`. Clients on this core
  read v2 but keep writing v1 until every client's read path is on this core; flipping it is a
  separate, gated release (task 1908).
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

### Added
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
  `UseApiNow`, as for a download; only "no answer" may pass. Both new outcomes are exported through
  WASM (`DirectOutcomeJs`) and UniFFI (`DirectOutcomeDto`; `Held { millis: Option }`); the Swift,
  Kotlin and header bindings are regenerated, and the docs of `Retry` and `ApiForThisFile` now say
  what they mean for an upload (do not hand an upload outcome to `direct_pinned_retry_decision`).
  Test vectors: 53 more `classify` rows in `direct_transfer.json` (63 -> 116, run by core, the WASM
  seams and the UniFFI exports) and the new `direct_upload.json` (24 grant answers, 8 commit
  answers, 5 init `transport` rows, 26 policy scenarios, the server constants it copies with their
  source lines), which is read by `upload.rs`'s tests ONLY. Every row names its source; 32 of the
  85 upload rows are the server's own status and body on that call at server main 30c8ed62; the
  others say what they are: 14 what a proxy or the framework sends (a bare 404, an HTML page, a
  redirect), 7 client-side cases (a server answer that exists but not on that call), 32 synthetic. Core's copies of the 4-grant cap and the lock TTL are pinned to
  that file; the server does not read it, so a server change turns no test red until the server
  adds its own assert.
  Not yet exported through WASM or UniFFI as functions: the CLI uses the Rust module directly;
  desktop, iOS and web adopt it in their own tasks.
- CI `Claims guard` job: runs the shared claims-guard engine plus
  `scripts/claims-guard/canon-sweep.sh`, the canon CLAIM_SWEEP over the whole tree
  (including any `design/` folder), so a false audit or compliance claim fails the build.

### Changed
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
- Nothing yet.

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
