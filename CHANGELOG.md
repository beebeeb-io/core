# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

### Fixed
- Discovery authorization answers (401/403) no longer consume or extend the routing-failure
  budget. Reauthentication leaves cached discovery and real transport failures unchanged;
  repeated authorization refusals no longer disable direct discovery for ten minutes.

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
