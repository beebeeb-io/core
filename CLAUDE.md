# beebeeb-io/core

Cryptographic core, shared types, and sync engine. This is the trust anchor — every client depends on this.

## Crates

- `beebeeb-core` — AES-256-GCM encryption, Argon2id KDF (256MiB/4iter/2par), BIP39 recovery phrases, HKDF per-file key derivation, onboarding (password policy evaluator, breach-check helper, signup ceremony state machine)
- `beebeeb-types` — CipherSuite, EncryptedBlob, KdfParams, ChunkMeta (shared across all repos)
- `beebeeb-sync` — Desktop sync engine: file watcher (notify), conflict resolution (KeepBoth default), selective sync

## Build & test

```sh
cargo test -p beebeeb-core   # unit + suite binaries (chunk_stream_parity, cli_auth_vectors, cross_client_vectors, cross_platform_vectors, direct_transfer_authority, integration, transfer_vectors, zip_tests) + doctests
cargo test --workspace       # full workspace (core + sync + types + upload + uniffi + wasm)
cargo clippy --workspace -- -D warnings
cargo fmt -- --check
```

The truth line is per binary: `test result: ok. N passed`. Count-history baselines are archived (details: docs/runbook/core-task-history.md).

## Key types

- `MasterKey` — 32 bytes, NOT Clone, zeroized on drop. Created from password (Argon2id) or recovery phrase.
- `FileKey` — 32 bytes, per-file via HKDF. `derive_file_key(master_key, file_id)`. `EncryptedBlob` — cipher_suite + nonce (Vec<u8>) + ciphertext (Vec<u8>).
- Owner per-file key conventions (SF-0002): `kdf::owner_file_key_for_name` tries the **string** id, then the legacy **binary** 16-byte UUID, then the read-only **upper_repair** (`UPPERCASE(id)`) convention, and reports which one won; `kdf::owner_file_key_for_content` does the same per content version from that version's first chunk frame. The shared readers (`decrypt_name_metadata`, `decrypt_file_metadata`, `decrypt_name_with_mime`) stay two-convention (string, then binary) — only the resolvers know `upper_repair`. A file is READ-ONLY if EITHER its name or ANY version reports `UpperRepair` — no rename, no new version, edits become a new file. Core never writes under it and never migrates a row.
- `encrypt_chunk(key, plaintext)` / `decrypt_chunk(key, blob)` — generic AES-256-GCM, NO associated data (key wrap, search shards). **Not for file content** (goes through `chunk_stream`) — **and not for names, thumbnails or file notes** (purpose subkeys: `encrypt_name*`/`decrypt_file_metadata`, `encrypt_thumbnail[_for]`/`decrypt_thumbnail`, `encrypt_note[_for]`/`decrypt_note`).

## Shared folder key id (`folder_key.rs`)

`folder_key::folder_key_id(folder_key) -> [u8; 32]` = HKDF-SHA256(ikm = folder key, salt = none, info = `b"beebeeb/folder-key-id/v1"`). One-way id so a server can compare folder keys without learning them. Not secret, must NEVER be used as a key; a new derivation gets a new info string (`v2`), never a change to this one. Exports: WASM `folder_key_id(Uint8Array)`, UniFFI `folder_key_id(Vec<u8>)` — both refuse non-32-byte keys. Vector: `folder_key_id` in `test-vectors/vectors.json` under the `test_vectors_v2` drift guard.

## Streaming chunk primitive (`chunk_stream.rs`)

`ChunkEncryptor` / `ChunkDecryptor` are the ONE shared chunk encrypt/decrypt loop for every client (cli, desktop, mobile/UniFFI, web/WASM) — no client re-implements it. Generic-free; `Send`; core stays synchronous (no tokio).

- Pull (native): `ChunkEncryptor::from_reader(...)` — peak memory ≈ one chunk. Push (WASM): `for_push[_with_chunk_size]` + `push_chunk`; `ChunkDecryptor::for_push` + `push_frame` mirrors it. `file_key` derived ONCE in the constructor, `ZeroizeOnDrop`.
- **Chunk-size cap:** `MAX_CHUNK_SIZE = 256 MiB`; the `*_with_chunk_size` constructors reject anything above (hostile server-dictated size → client OOM guard).
- **`finish()` integrity guard:** requires `emitted == chunk_count` AND `running_ciphertext == file_size + 28*chunk_count`. Detects a SHRUNK source; a GROWN source is caught one level up in `file_encrypt::encrypt_file_to_chunks`, which re-stats the input after `finish()`. Silent truncation is a return-typed error on every client.
- **Wire format:** `nonce(12) || ciphertext || tag(16)`, fresh random nonce per chunk. New files are written as **v1** during the read-only rollout (`WRITE_FORMAT`, task 1908); every reader reads v1 and v2.
- `file_encrypt::encrypt_file_to_chunks` DELEGATES to `ChunkEncryptor`; `tests/chunk_stream_parity.rs` enforces identical chunk plan + WRITE_FORMAT stream.
- The three legacy decrypt functions (`encrypt::decrypt_chunks_to_file`, `encrypt::decrypt_contiguous_to_file`, `file_encrypt::decrypt_chunks_to_file`) are disk/legacy paths, NOT superseded; ALL write to a sibling `.tmp` and `rename` onto the final path only on full success — no partial plaintext survives a failed decrypt.
- **WASM binding:** `WasmChunkEncryptor` wraps the push form (JS slices the `File`); `pushChunk` returns the full frame; `finish()` runs the integrity guard. `WasmChunkDecryptor` (or `decrypt_chunk_frame` for random access) is required for web file content, not the generic `decrypt_chunk`.

**Resumed uploads:** `resume_policy(stored, writing)` → `SessionResume::ContinueSession` ONLY for `(Some(V1Legacy), V1Legacy)`; everything else (including a record that doesn't name its format) is `RestartWithFreshSession` — never PUT into the old session again; upload from chunk 0 into a new session. A client told to restart MUST first `POST /api/v1/files/{id}/upload/abandon` (or wait out the lease, default 3600 s) and only then init again; a 409 from that init means retry abandon/wait — never fall back to the old session. Clients persist `ChunkEncryptor::format()` next to the session id.

## Chunk format v2 — position binding (task 1908)

v1 frames had no AAD: within one file a malicious server could reorder/duplicate/drop/truncate/splice frames undetected. v2 = same frame layout, own subkey, AAD = position (STREAM; as in age/Tink):

```text
key = HKDF-SHA256(ikm = file_key, salt = none, info = "beebeeb/chunk/v2/key")
AAD = "beebeeb/chunk/v2"         16 bytes: domain tag + version
   || u32_be(len(file_id))       length prefix (injective encoding)
   || file_id                    exact bytes fed to derive_file_key (string UUID)
   || version_id                 12 bytes: the nonce of THIS upload's frame 0
   || u32_be(chunk_index)        0-based
   || u8(is_last)                1 on the final chunk only
```

- v2 frames never use the raw file key (key separation — no blob of another type opens as a v2 frame). `version_id` = frame 0's random 96-bit nonce (Guus's 1778 ruling: file VERSION id in the AAD). Deliberately NOT stored in file metadata; it does not prevent whole-version rollback either.
- No total count in the AAD — the last flag gives the same truncation guarantee. `file_id` is in the AAD although the key already binds it — defence in depth.
- **Mandatory pin:** every content reader REQUIRES `ExpectedChunkFormat` from the file's encrypted metadata via `decrypt_file_metadata[_with_key]` (refuses plaintext names; folders keep `decrypt_name_metadata`): `V2` = only v2 frames open; `Unrecorded` = frame 0 decides then LOCKS (residual: a server can still pass a no-AAD blob off as the whole file at position 0 — documented).
- **Writers record the format** with `encrypt_name_with_chunk_format` (`recorded_for(enc.format())`); rename/replace carry forward the decrypted value — never upgrade a file id with v1 history, never drop a recorded 2; unknown recorded values are errors, never fallback to detection.
- **Metadata sealing (names, thumbnails, notes):** name/thumb/note subkeys (`beebeeb/name/v1`, `beebeeb/thumb/v1`, `beebeeb/note/v1`) replace raw-key sealing; readers try the subkey then the legacy raw key; clients must NOT open names/thumbnails via `decrypt_metadata`/`decrypt_chunk`. ONE rule for content, names, thumbnails: `chunk_stream::chunk_format_for_pin(pin)` then `encrypt::metadata_seal_for(format)`. Deviation from the round-3 ruling is recorded in task 1908; both switches flip in ONE gated release. Thumbnails only via `encrypt_thumbnail[_for]`; notes only via `encrypt_note[_for]`/`decrypt_note`.
- **Decrypt rules (`StreamOpener`):** frame i opens only at index i and (v2) under frame 0's version id; nothing may follow the last frame; `finish()`/EOF fails unless a v2 stream saw its last frame; zero frames is an error. Trial opens are safe (tag checked before keystream).
- **Random access:** `open_chunk(file_key, file_id, version_id, index, is_last, format, frame)` — format from the metadata pin, version_id from `ChunkDecryptor::version_id()` (or chunk 0's first 12 bytes).
- Generic no-AAD (`encrypt_chunk`/`decrypt_chunk`/`*_raw`, WASM `decrypt_chunks`) stays for key wrap, search shards, v1 content — never to SEAL a name/thumbnail/note under a per-file key.
- **Residual (decision 1912):** pre-switch legacy names/thumbnails under the same raw key as v1 content remain servable as content; old blobs cannot be retired by rewriting.

### Client adoption checklist (every client, before it ships on this core)

1. Read the content pin with `decrypt_file_metadata[_with_key]` (never `decrypt_name_metadata`, never a server field) and pass `chunk_format` to every content reader.
2. Take the chunk format from the pin (or a decryptor that opened chunk 0), never from a server value; prefer `version_id()` over re-reading chunk 0's first 12 bytes.
3. Call `finish()` after the last frame and DISCARD all plaintext on any `Err`.
4. Every replace/new version uses the file's recorded pin (`with_recorded_pin`/`apply_recorded_pin`/`withRecordedPin` — `V2` ONLY from an EXISTING file's authenticated metadata); a NEW file never does (lead ruling 2026-10-17). If the pin cannot be read, do not upload. Each client ships a test that its new-file path never passes `V2`.
5. Record the format at upload of a NEW file; on rename/replace carry forward what `decrypt_file_metadata` returned.
6. Thumbnails/notes only through `encrypt_thumbnail[_for]` / `encrypt_note[_for]` / `decrypt_note`; names only through the `decrypt_name*` / `decrypt_*_metadata` readers. Notes: write with `encrypt_note_for(file_key, text, pin)`, read with `decrypt_note` — never `encrypt_metadata`/`encryptFilename`/`encrypt_chunk` for a note.
7. Resuming: ask `resume_policy(stored_format)` and obey it; persist the encryptor's format with the session id.

**Rollout (read-only phase now):** `WRITE_FORMAT = ChunkFormat::V1Legacy`; the v2-write switch is a separate gated core release once every client's read path is live. Switch gate (server): reject replace inits, `PATCH name_encrypted` and `PATCH note_encrypted` from clients older than 1908 round 4/round 5.

## WASM target gating

`beebeeb-core` builds for `wasm32-unknown-unknown`; `rusqlite` (fp_cache only) is gated to non-wasm (`[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` + `#[cfg(not(target_arch = "wasm32"))]` on `pub mod fp_cache;`). WASM JsValue returns serialize via typed `#[derive(Serialize)]` structs, not `Map`s.

## UniFFI handles (`beebeeb-uniffi`) — mobile/desktop

`ChunkEncryptorHandle` / `ChunkDecryptorHandle` wrap the primitive for Swift/Kotlin. Key derived IN CORE from a borrowed `&MasterKeyHandle` — raw key bytes never cross FFI. **Single-consumer contract:** a handle is an ordered cursor driven from ONE sequence; the `Mutex` is only UniFFI's Send+Sync backstop. `finish()` consumes the handle. Regenerating bindings: `build-ios.sh` / `build-android.sh`; grep the regenerated header for every new symbol before shipping (the 0426 12-symbol drift lesson).

### Folder-link handles (task 2237c)

Folder keys are random (`FileKeyHandle.generate`, OS CSPRNG), never derived from
the master key. Clients fetch permanent owner custody before minting a key.
`wrap_key` / `unwrap_key` keep keys in native handles: AES-256-GCM, no AAD,
`nonce(12) || ciphertext(48)`; unwrap rejects every plaintext length except 32.
`key_id` is core's one-way folder-key id, never the key itself.

`from_folder_link` combines the 32-byte URL fragment `K_c` and an optional
32-byte stretch with `combine_folder_link_key`. `from_folder_link_passphrase`
stretches with Argon2id v19 (256 MiB, 4 iterations, 2 lanes, 32 bytes), salt =
`SHA-256(UTF-8 token || "beebeeb-folder-link-passphrase-v1")[0..16]`, then combines.
Passphrases are NFC-normalized in core and empty strings are rejected. KDF
errors propagate; clients must never downgrade to an unprotected link. Argon2
uses a try-reserved explicit block buffer, zeroized on drop with argon2's
`zeroize` feature. Allocation failure returns a KDF error (OS process termination
cannot be caught).

L6 supersedes the original custody/owner-wrap rule. `wrap_folder_custody` /
`unwrap_folder_custody` derive a purpose key using HKDF-SHA256 (no salt, master
IKM), info = `beebeeb-folder-custody-v1` || folder-id bytes, and bind the same
bytes as AES-GCM AAD. Link owner recovery uses `beebeeb-link-owner-key-v1` ||
share-id bytes for K_c and `beebeeb-link-owner-token-v1` || share-id bytes for
token UTF-8. UniFFI takes canonical id strings as UTF-8. Never fall back to the
legacy file-key custody opener after authentication fails; an existing invite
may be opened separately for seeding only. MasterKeyHandle exposes these wraps
plus legacy `wrap_key` / `wrap_bytes` without exporting the master key.
WASM (2237b) exports the same wraps in the L7 byte style, wire = nonce(12) ||
ciphertext+tag, record id = the canonical id string as UTF-8:
`wrapFolderCustody` / `unwrapFolderCustody` (60-byte wire),
`wrapLinkOwnerKey` / `unwrapLinkOwnerKey`, `wrapLinkOwnerToken` /
`unwrapLinkOwnerToken`, and `deriveFolderLinkPassphraseStretch` (NFC + empty
refusal in core). They take the master key as 32 bytes like the other byte-key
exports; task 2254 moves them to handles. Pinned by
`beebeeb-wasm/js-tests/folder_owner_wraps.test.cjs` against vectors v10.

Unreleased vectors v10 include the original two families, an NFD-equality row,
and three purpose-wrap families. Python argon2-cffi/cryptography independently
produces all six; WebCrypto verifies the new purpose keys, AAD and ciphertext.
The core drift guard regenerates them. Owned secrets and scratch memory are
zeroized on success and error paths.

## Owner file-key adoption (L8)

`owned_keys::wrap_owner_file_key` / `unwrap_owner_file_key` use the KDF purpose helpers:
HKDF-SHA256(master, no salt, info = `beebeeb-owner-file-key-v1` || item ID UTF-8 bytes), with that exact context as AES-GCM AAD.
IDs use the same textual encoding as L6 custody, never the binary UUID encoding of L7.
Wire: nonce(12) || ciphertext+tag(48); the opener requires exactly 32 authenticated bytes.
The old owner-adoption entry points and generic opener are removed; `resolve_owned_key` reads only L8 owner wraps.
There is no legacy owner-wrap fallback (plan C L8: this flag-on format was never enabled in production).
UniFFI `MasterKeyHandle::wrap_owner_file_key` takes a `FileKeyHandle`; its opener returns a handle.
WASM `wrapOwnerFileKey` / `unwrapOwnerFileKey` follow the L6 byte-array API; client binding regeneration and core pin bumps follow in client PRs.
The independent Python generator is `test-vectors/tools/make_owner_file_key_vector.py`.

## Encrypted client metadata (`client_meta.rs`) — task 1922

Client-supplied free text (device hostname, session name/local path/remote path) is sealed under the
user's key; the server stores and returns only `bbcm1.` envelopes plus client-generated record keys.
- **Key:** one per user, `HKDF-SHA256(ikm = master, salt = none, info = "beebeeb/client-meta/v1/key")`, held as a `FileKey` and private to the module. `ClientMetaKey` is the opaque handle the bindings use; the derived key is never exported (a `FileKey` would also fit `encrypt_chunk`).
- **AAD:** `"beebeeb/client-meta/v1"` (22 bytes) `|| u32_be(36) || record_key` (lowercase hyphenated UUID) `|| u32_be(len(device_key)) || device_key` (36 bytes, or empty) `|| u8(field)`. `device_key` is empty for field 1 and required for fields 2-4; any other combination is `InvalidInput`.
- **Payload:** `u16_be(len) || UTF-8 || zeros` to `max(32, roundup(2 + len, 32))`; `len > 1024` is `InvalidInput` and `open` requires the exact padded length. Paths longer than 1024 bytes are shortened by `fit_for_seal` (last 1021 bytes on a char boundary behind `…`), never per client.
- **Envelope:** `"bbcm1." + base64url-no-pad(nonce(12) || ciphertext || tag(16))`, AES-256-GCM with a fresh `OsRng.try_fill_bytes` nonce (an RNG failure is an error, never a panic). Open matches the prefix case-sensitively, accepts at most 1452 chars, and requires 60..=1084 decoded bytes with `(len - 28) % 32 == 0`.
- **Field codes:** 1 device hostname, 2 session name, 3 session local path, 4 session remote path. Codes 5/6 stay reserved and are refused (`current_file`/`detail` are discarded from S1, never sealed).
- **Bindings:** WASM `ClientMetaKey` handle (`seal` / `open` / `openMany`; `field` is a checked `u32`, and UUID strings are parsed and re-rendered lowercase hyphenated) and UniFFI `MasterKeyHandle::seal_client_meta` / `open_client_meta` / `open_client_meta_many`. `fitForSeal` (WASM) / `fit_for_seal` (UniFFI) shorten a string before sealing. No free function takes the master key for this feature; the batch derives once and a bad row (null envelope, bad field/UUID/shape, failed open) is `ok: false` for that row only — a cleared key handle is an error for the whole call.
- **Residuals (accepted):** the server can replay an older envelope for the same record and field, or delete a field; both are display-only and a stateless viewer cannot detect them. The hostname is encrypted too, so admin/push see platform and client kind only.
- Vectors: `test-vectors/vectors.json` **version 13** carries `client_meta_device_hostname`, `client_meta_session_paths` and `client_meta_padding_buckets`, generated by the real seal path through the `cfg(test)` / `test-support` fixed-nonce seam and pinned by the `published_v2_vectors_match_core` drift guard plus the `cross_platform_vectors` consumer tests.

## Encrypted search index (`search_index.rs`)

Client-built, E2E-encrypted file-name search; the server is zero-knowledge, everything runs on-device, identically for every client. `tokenize(name)`: NFKD + accent-fold + separators + camelCase, dedup preserving order; keeps the full normalized name for substring fallback.
- `SearchIndex`: `build`, incremental `upsert`/`remove` (return the dirty bucket set), `query` (exact + prefix + substring).
- Sharding: `bucket = blake3(key)[..8] % num_shards` (`DEFAULT_NUM_SHARDS = 64`), pages ≤ 128 KB after encryption; `num_shards` fixed per index.
- Encryption: per-shard key `kdf::derive_search_index_key` (HKDF label `beebeeb-search-index-shard-v1`, distinct from the file-key label); `blob = nonce||ciphertext||tag` via `encrypt_chunk_raw`.
- Bindings: UniFFI `SearchIndexHandle` + WASM `WasmSearchIndex` (same surface); sync helper `search_sync::diff_manifest` (`searchIndexSyncPlan`). Dependency: `unicode-normalization` (NFKD). WASM constructors accept at most 64 shards (zero still normalizes to one), matching `deriveSharedFolderIndexKey` buckets 0–63.
- Wiring: WEB is wired (task 0871). Follow-ups: mobile wiring; retiring `/api/v1/index` (Guus-gated, after web + mobile both cut over); Part A recursive in-app search.

## CLI login handshake (`cli_auth.rs`)

Device-authorization crypto for `bb login` — separate from OPAQUE. P-256 ECDH → HKDF-SHA256 (info `beebeeb-cli-auth-v1`) → AES-256-GCM; byte-identical to web's WebCrypto. `decrypt_cli_payload()` falls back to the raw shared secret (legacy v0.4 web). **Wire format is pinned, no protocol change** (`tests/cli_auth_vectors.rs` + `cli/tests/ecdh_compat.rs`) — changing the info string / point encoding is a coordinated cross-client migration, never a refactor.

## Onboarding module (`onboarding/`) — task 1744

Signup ceremony state machine driven by the server's onboarding document; no new cryptographic primitive; no I/O; core stays synchronous and WASM-clean. Rules that bind every client. `PasswordPolicy::from_server(min_length)` — `MIN_LENGTH_FLOOR = 12` is a floor applied inside `from_server` (the server may raise, never lower); no hard-coded fallback policy. Unicode-scalar length; evaluator is advisory UX + client-side gate, breach check is the backstop.
- `onboarding::breach` — k-anonymity (SHA-1 prefix only; suffix never leaves the device). **The HTTP call stays in each client and goes to Beebeeb's own endpoint** (`GET /api/v1/auth/pwned-range/{prefix}`) — the public HaveIBeenPwned API violates the no-US-systems rule (task 0995). Empty/whitespace body, body > 256 KiB, non-2xx, or a malformed line is an OUTAGE (a captive portal must not read as clean); `fail_open` from the document picks Allowed vs Blocked. `BreachCheck::record` refuses a prefix that isn't this password's (`breach_prefix_mismatch`).
- `SignupCeremony` steps: VerifyEmail (if required) → SetPassword → SavePhrase → ConfirmPhrase → CreateAccount → Done; ONLY `create_account` is gated. The breach gate is enforced here, once: a stale (`breach_check_stale`) or answer-less (`breach_check_missing`) check is refused and the verdict is computed from the stored password — a client cannot pick `fail_open`. No notion of email address in the ceremony.
- Memory: password/phrase are `Zeroizing`; **clients must call `wipe()` (`abandon()` in the bindings) on back, cancel and error exits** (binding handles are freed on the host's schedule). `phrase()` copies are render-only. Bindings: WASM (`WasmSignupCeremony`, `WasmBreachCheck`, `evaluate_password`; owned strings in `Zeroizing`) and UniFFI (`SignupCeremonyHandle`, `BreachCheckHandle`, separate `OnboardingError`). Tests are trusted only after mutation.

## Direct S3 transfer rules (`direct_transfer/`) — task 2173

The client-side rules of the direct S3 transfer contract v1 (workspace spec `docs/specs/2026-10-23-direct-download-hosts.md`, amendments R1.1–R1.18) as **pure Rust**: no I/O, no HTTP client, no clock, no async runtime. Each client keeps its own HTTP stack (CLI reqwest, desktop `beebeeb-sync`, iOS `URLSession`, web `fetch`) and calls these, so five clients do not re-implement them. Plain owned data only, so WASM and UniFFI export it unchanged (below).

- `wire`: tokens `object-download-v1` / `object-upload-v1`; `X-Beebeeb-Capabilities` goes on grant/init requests ONLY, never globally; serde types. The upload grant and commit types are checked against the merged server routes (server #331 at `3e7ca039`; the vector bodies are the server's real ones, each row names its source line). Grant types `Debug`-print their URL without its query.
- `authority::check_storage_url`: a strict printable-ASCII grammar, so what was checked is what any URL parser connects to (https; a listed `{host, bucket}` in path style; no userinfo, IP-looking host, unlisted port or dot segment; http only to loopback when the API base is loopback http). `redact` / `scrub` are the only ways a URL, or text that may contain one, reaches a log, error or progress line.
- `classify`: R1.6. Only a JSON-bodied 404 (JSON content type AND an `error` string) is terminal; a bare/HTML 404, 405, 5xx or no answer means "no direct transport on this node". 409 `direct_unavailable` / `replace_in_progress` / unknown → API for this file; `version_unavailable` → restart; 429 → back off (Retry-After clamped 1–120 s); 401/403 → terminal. `Call::PinnedChunk` (`GET /files/{id}/chunks/{i}?object_version_id=`) is classified here too and differently: ANY 409 except `replace_in_progress`/`commit_in_progress` (a wait) is `Restart` — the server's body for a gone pin is a sentence, not a code, so the status is the contract; 429 → back off; 5xx / bare 404 / 405 / no answer → `Outcome::Retry` (a 5xx that sends `Retry-After`, as the server's 503 does, is a stated `Backoff` instead); 401/403/JSON 404 → terminal; other 4xx → the API stream. `PinnedRetry::decide` is the one retry policy (4 attempts, 150 s of waiting in all so the server's real `Retry-After: 60` 429 fits more than once, a stated wait kept, otherwise 1 s doubling) so no client hand-rolls it.
- `upload` (`object-upload-v1`): the client's side of one chunk of a direct upload (grant -> PUT -> commit). `UploadGrant::from_answer` / `UploadCommitted::from_answer` decode and validate the server's `200` bodies (same index, same size, a `Link` passes `check_storage_url`; `skipped` is write-once: nothing to send), `put_stored` says any 2xx from storage is stored, and `UploadChunkState` is the retry policy of ONE chunk, answering every failure with `UploadNext::{Retry, UseApi, Terminal}`: at most `MAX_GRANTS_PER_CHUNK` = 4 grants; the 8th failure of any kind ends the tries (7 are ridden out); 150 s of waiting in all; the client's own backoff is 1 s doubling with equal jitter (`UploadChunkState::with_seed`, one random seed per chunk; the seed-0 `new` exists in test builds only, because it would give every chunk of every installation the same stream), a server-stated `Retry-After` is kept exactly. A session's transport never changes after init, so there is no "this chunk goes through the API" inside a direct session: `UseApi` means abandon the session and init again WITHOUT `X-Beebeeb-Capabilities`. `Call::UploadGrant` / `Call::UploadCommit` classify as `classify` does for the download calls, except: a commit `409 chunk_not_stored` is `Outcome::Regrant` (the PUT did not land: ask for a link again, within the cap); a commit `409 commit_in_progress` is `Outcome::Held(stated wait)`; a 1xx/3xx is `ApiForThisFile` (a wrong path: this session cannot go direct) and only status 0 (no answer) may pass. **A hold is not a failure.** After a copy that failed the server keeps the chunk's commit lock for its whole TTL (`COMMIT_LOCK_TTL` = 420 s = 4 x 90 + 60, server `direct_transfer.rs:410-412`, R3.1), so `commit_in_progress` can last minutes: `UploadChunkState` waits it out on an allowance of its own (`hold_budget` = TTL + 30 s = 450 s, polling 5 s doubling to 15 s with equal jitter, or the stated wait; the last poll is cut to what is left, then `UseApi`) that does not touch the 7-failure cap or the 150 s budget. A poll never waits less than a second (`MIN_HOLD_POLL`: a stated or configured 0, or a 0/negative/NaN number from a binding, would otherwise loop for ever) and there are at most `hold_max_polls` (450). The server also answers `commit_in_progress` when its lock is already released if the record's HEAD could not tell (R3.4, `routes/direct_transfer.rs:1123`): there every poll re-copies the chunk, so the allowance is also the bound on that case; the agreed server change (s3-server, after #338) answers every R3.4 transient as `503 {"error":"storage_unavailable"}` with `Retry-After: 5` (a stated, counted wait: `Backoff`, never `Held`) and keeps `commit_in_progress` for the lock alone, with `Retry-After` = the lock's remaining TTL in [1, 420] (`Held(Some(that))`, clamped to 120 s per poll); the vectors have rows for both, labelled as that PR. The two server constants the client copies (the 4-grant cap and the lock TTL) sit in `test-vectors/direct_upload.json` under `constants` with their server source lines, and core tests fail if core's copies differ from that file. **Only core's side is pinned**: that file is read by `upload.rs`'s own tests (exact row counts) and by nothing else (not the server, not the WASM or UniFFI exports), so a change on the server turns no test red; the server-side assert is a proposal for the s3-server lane. `Outcome` and `Call` are `#[non_exhaustive]`: a binding's catch-all arm would map `Regrant` or `Held` to `UseApiNow` without a compile error, which the vector runners (the `direct_transfer.json` classify rows) and the round-trip tests are there to catch. The native upload types are not exported through WASM or UniFFI yet (only `classify`'s new call codes and the two new outcomes are), so a host must not pass an upload outcome to `direct_pinned_retry_decision`.
- `window::DownloadPlanner`: windows of grants (refill at ≤ 2 unused), ≤ 4 chunk requests in flight and no chunk further ahead than that (the decryptor is in-order), grants unused inside a 30 s margin, ≤ 3 renewals per chunk then the pinned API route, one API re-fetch of a chunk that fails authentication before `Verdict::Corrupt`. Every grant is checked against the response geometry and `check_storage_url` before the caller sees it. Time and jitter are injected. A file that comes to more than one verdict keeps the strongest (`Corrupt` > `Terminal` > `Restart` > `ApiForFile`, the first among equals): every writer goes through `set_verdict`, so a stale window answer or a failure reported out of order cannot turn a corrupt chunk, a revoked grant or a changed version into `ApiForFile`. `DiscoveryCache` forgets everything after `DISCOVERY_TTL_MS` (a good answer, a JSON 404 `NotSupported`, and two failed attempts), so a long-lived client probes again after ten minutes instead of staying off the direct transport until it restarts.
- `window::DownloadPlanner`, the storage breaker and the byte cap (clients plan A1, decisions D19 and D23): when a chunk uses up its renewals and **no chunk of the transfer has come whole from storage** (a fetch through the pinned API route does not count), `storage_given_up()` turns true and the planner goes `api_only`: every chunk still waiting for a link, or holding one it has not used, becomes a `FetchViaApi` poll, and a window answered after the trip is not used. After one storage success the per-chunk rules apply alone. The caller records the trip with `DirectHealth::gave_up(Download, ..)` when the file ends; `storage_given_up()` reads false again if a chunk that was already in flight then arrives from storage (storage delivered bytes in this transfer, so no hold). `PlannerConfig::max_in_flight_bytes` / `set_max_in_flight_bytes` bound the chunks HELD (fetching plus fetched and not yet consumed, i.e. the reorder window `limit()`, not just the outstanding requests) to `clamp(floor(bytes / (chunk_size + 28)), 1, 4)`: 64 MiB holds four 4 MiB chunks, three 16 MiB chunks (the 28 bytes count) and one chunk of 64 MiB or 256 MiB; `None` keeps four.
- `timeouts` (clients plan A2): `STORAGE_CONNECT_TIMEOUT` 15 s, `STORAGE_GET_IDLE` 30 s (a PUT has no idle timer), `DISCOVERY_TIMEOUT` 15 s, `API_CALL_TIMEOUT` 60 s, `BACKGROUND_PUT_RESOURCE_TIMEOUT` 240 s, and `storage_put_total(len)` = `storage_get_total(len)` = `60 s + ceil(len / 131072) s` over the **ciphertext** length. A test holds the PUT total under the server's late-write fence `max(300, ceil(len * 8 / min_uplink) + 60)` for every chunk length up to the largest chunk (256 MiB + 28), using the server numbers recorded with their source lines in `test-vectors/direct_upload.json` `constants` (`url_ttl_seconds`, `put_allowance_floor_seconds`, `upload_lease_seconds`, `max_ciphertext_chunk_bytes`); another test holds the 240 s background timeout under the allowance floor minus 60 s, which has to hold from a start as late as the link's expiry.
- `health` and `resume` (clients plan A1, decisions D19 and D25): `DirectHealth` remembers, per `Direction`, when a transfer last gave up direct; `may_start` is false for one discovery trust period (ten minutes) after it, `may_start_file(.., file_gave_up)` is also false for a file that gave up itself, `last_gave_up_ms` / `restore` persist the two timestamps, and a recorded time in the future counts as expired. `resume_transport(recorded, discovery, forced_api)` is the rule for an unfinished upload found on disk: an API session continues on the API; a direct session continues direct only when discovery offers upload, is given up (`AbandonToApi`) only on a definite no (forced API, `Offers { upload: false }`, a JSON 404), is kept and fails the file for this run on `Unknown` (a 5xx, a timeout, a bare 404 says nothing about the session), and is kept and sent to sign in again on `Unauthorized` (401/403).
- `storage`, `pacing` and `context` (plan K1): `check_storage_get` stores a chunk only for a `200` whose `Content-Length` is exactly the grant's length and `check_storage_body` only when the counted bytes are equal too (anything else `Failed { status }`, `0` = no HTTP answer; `kind()` is `"stored"`/`"failed"`); `StorageBody` counts a stream as it arrives and a refused `push` latches (the body is overflowed, so every later push is refused and `finish` fails, even if the counted bytes happen to equal the grant); a binding's storage-body failure carries the `status` from the body itself, never from the caller's input; `paced_until_ms` is desktop's ceiling formula (`kbps` is KiB/s, `0` = `i64::MIN`, saturating; WASM crosses it as `f64` with `-Infinity` for no ceiling); `max_in_flight_bytes` is 256/64/64/16 MiB for `Native`/`Browser`/`MobileApp`/`MobileExtension`; `pairs_allowed` requires the direction offered, at least one discovery storage pair, and every pair allowlisted (host ASCII case-insensitive, bucket exact; an empty list is not allowed vacuously). Bindings: WASM `checkStorageGet` / `checkStorageBody`, `pacedUntilMs`, `maxInFlightBytes`, `pairsAllowed`, `WasmDownloadPlanner.chunkLength`; UniFFI `direct_check_storage_get` / `direct_check_storage_body`, `direct_paced_until_ms`, `DirectMemoryClassDto` / `direct_max_in_flight_bytes`, `direct_pairs_allowed`, `DirectDownloadPlannerHandle::chunk_length`; `directTransferConstants()` / `DirectConstantsDto` gain `max_discovery_body_bytes`, `max_grant_body_bytes` and `max_chunk_body_bytes` (256 MiB + 28). The vector sections `storage_get`, `storage_body`, `pacing`, `pairs_allowed` and `memory_class` run on native, WASM and UniFFI.
- Bindings: `beebeeb-wasm` (`WasmDownloadPlanner`, `WasmDirectDiscoveryCache`, `WasmDirectHealth`, `WasmStorageBody`, `checkStorageUrl`, `classifyDirectAnswer`, `parseDirectDiscovery`, `redactUrl`, `scrubText`, `directTransferConstants`, `directDownloadGrantsPath`, `resumeTransport`, `storagePutTotalMs`, `storageGetTotalMs`) and `beebeeb-uniffi` (`DirectDownloadPlannerHandle`, `DirectDiscoveryCacheHandle`, `DirectHealthHandle`, `DirectStorageBodyHandle`, `direct_*` functions) are thin type converters over this module; no rule lives in them. Enum-like values cross as the stable `code()` / `kind()` strings of the core types; failures carry a code and never a URL; the planner is a handle (one sequence's cursor, fed `now_ms` on every call). The presigned link is never a string past the binding: WASM `WasmSignedUrl` and UniFFI `DirectSignedUrl` print scheme and host only and give the link through `raw()`; a `WasmSignedUrl` is not structured-cloneable (send a worker `url.raw()`), a Kotlin `toString()` after `destroy()` throws, and `DirectSignedUrl`, `DirectChunkGrantDto` and `DirectPollDto` deliberately export NO `Eq`/`Hash`: UniFFI 0.31.1's Kotlin `equals`/`hashCode` lower the handle with no destroyed check (a use-after-free on a released link), so compare `raw()` (the test `the_committed_bindings_carry_the_signed_url_surface` pins the generated text, including the absence). The `.d.ts` types `poll()` as `DirectPoll` (a `typescript_custom_section`; `js-tests/types.check.ts` pins what a TypeScript consumer sees). A wrapper that cannot run without a JS engine calls a plain-Rust seam the tests run; the JS-facing paths themselves (the module loads, `poll()` hands out a `WasmSignedUrl` whose `String()`/`JSON.stringify`/`util.inspect` never show the link, the seed through `Math.random()`) are run under node by `beebeeb-wasm/js-tests/run.sh` (builds BOTH `--target nodejs` and `--target web` into a temp dir, `node --check`s the glue, `tsc --noEmit`s the `.d.ts` files and runs `node --test`; needs wasm-pack, node >= 20 and tsc; CI job `wasm-js`). Never put a block-comment token (`/*` or `*/`) in a `///` doc comment of `beebeeb-wasm` or `beebeeb-uniffi`: it is copied into a JSDoc block in the generated glue and `.d.ts` (a closer ends the block early) and into Kotlin/Swift doc comments (an opener starts a nested one); the test `no_doc_comment_contains_a_block_comment_token` in each crate fails on it.
- Vectors: `test-vectors/direct_transfer.json` (authority, classify (the upload-call rows among them), redact, scrub, chunk-length, pinned-retry, discovery-cache, planner-scenario, `health` and `resume_transport` rows) is run by ONE interpreter, `direct_transfer::vectors` (`test-support`), through core, the WASM seams and the UniFFI exports. Each run asserts the per-section row COUNT equals the file's, so a skipped section is a failure, and `the_runner_goes_red_when_a_surface_drifts` proves the runner can fail. A rule change adds its row in the generator and regenerates the file; a client that disagrees fails its own binding test. `test-vectors/direct_upload.json` (grant answers, commit answers, init `transport`, policy scenarios, constants: the server numbers with their source lines and the client time bounds) is read by `direct_transfer::upload`'s and `direct_transfer::timeouts`' tests alone. Every upload row of either file has a `source` (a test enforces it): "server 30c8ed62 ..." is the server's own status and body ON THAT CALL with file and line (and the server test that asserts it); anything else says it is `synthetic` (a proxy, a framework fallback, a broken server), a `client-side case` (a server answer that exists, but not on this call or not with this header), a spec rule, or `client policy`. Both files are generated by `test-vectors/tools/make_direct_transfer_vectors.py` and `make_direct_upload_vectors.py` (`python3 test-vectors/tools/make_direct_upload_vectors.py test-vectors/direct_upload.json`): rows are added in the generator, never in the JSON. `test-vectors/tools/check-direct-vectors-generated.sh [PATH]` fails when `PATH` (default `direct_transfer.json`) is not byte-for-byte what its generator writes; its `--self-test` runs that same gate on the committed file, which must accept it, then on a temporary copy with the first `"expected"` digit changed, which must exit 1 (any other outcome exits non-zero), so the JSON is never edited by hand. The policy waits that carry jitter are computed by `test-vectors/tools/jitter_port.py`, an independent Python port of the jitter rule, not by running the Rust.
- Tests: the `direct_transfer::` unit tests and `tests/direct_transfer_authority.rs` (hostile-URL table; a differential fuzz against the `url` crate). Every rule has a recorded mutation that fails a named test (task 2173 notes); a new rule needs one.

## L2 driver (`beebeeb-transfer`) — task 2173, plan K1/K2

`beebeeb-transfer` is the transport-independent driver above core's pure rules, shared by the CLI and desktop (and later bindings): one `download()` call takes any `DirectIo` implementation and performs the plan. It owns no rule — the planner, classifier, retry policy, timeouts and body counter all come from `beebeeb-core::direct_transfer`.

- `DirectIo` is the whole transport seam: `api` (adds the caller's `Authorization` and client headers), `storage_get`, `storage_put`, `sleep`, `wall_ms`, `mono_ms`. `StorageGet` takes a `SignedUrl` whose `Debug`/`Display` print only scheme and host, so a URL cannot reach a log or error through the driver.
- Storage GETs are bounded by `storage_get_total(ciphertext_len)`, idle for `STORAGE_GET_IDLE`, read at most `expected_len + 1` body bytes, and report `status: 0` for any transport error. The conformance suite checks that contract: no redirect is followed, no cookie is sent, no `Authorization`/`X-Beebeeb-*` header reaches storage, an idle body and an exceeded total both end as status 0, an overlong body is visible as one byte too many, and a plain-http non-loopback link is refused.
- Every storage body is judged by `StorageBody::from_head` / `push` / `finish`; only `Stored` is `fetch_ok`, anything else is `fetch_failed`. The driver does no length comparison of its own.
- The pinned per-chunk route is `Call::PinnedChunk` with core `PinnedRetry::default()` (4 attempts, 150 s of waiting); its body read is bounded by `storage_get_total(len)`, not `API_CALL_TIMEOUT`.
- `DirectStore::global()` is a `OnceLock` keyed by `(api_base, account_id)`; entries share discovery cache and breaker health, and `forget_account` drops every entry of one account. `HealthSnapshot` stores wall-clock timestamps; the driver records breaker trips on `mono_ms` and converts at the boundary.
- Plaintext reaches the sink only after the chunk authenticates, in order; nothing is published on `FileChanged`, `Unauthorized`, `Forbidden` or `Unauthentic`, and a fallback returns `UseApi` with the reason. Pacing uses `paced_until_ms` over monotonic time. No event, error or `Debug` string carries a URL.

## Security invariants

- MasterKey and FileKey are NOT Clone — prevents accidental key copies in memory
- All intermediate key buffers use `Zeroizing<[u8; 32]>` — zeroed on drop
- Each file gets its own key via HKDF(master_key, file_id) — limits blast radius
- Recovery phrase IS the master secret — password wraps it, doesn't replace it
- No panics in crypto paths — everything returns Result

## Design references

Design files live in the workspace root `../../design/hifi/` — never copy them into this public repo (a snapshot once published a false external-audit claim; the Claims guard CI job now fails on those strings).

## Claims guard

- `bash scripts/claims-guard/claims-guard.sh` — shared engine + `policy.conf`, vendored verbatim from the workspace (edit the workspace canonical, re-copy). Exceptions: `.claims-allow`.
- `bash scripts/claims-guard/canon-sweep.sh` — canon CLAIM_SWEEP over the whole tree; must print `clean (0 rows)`; `--self-test` proves it goes red.

## License

AGPL-3.0-or-later

## How we work (evidence, design, done, parallel agents)

The full rules live in the workspace `CLAUDE.md` → "How we work". The repo-specific instantiation:

- **The count-shaped truth line:** `cargo test --workspace 2>&1 | tee /tmp/bb-core-test.log` → one `test result: ok. N passed; 0 failed` per crate/suite; assert the Ns — a suite that did not run is a red.
- **Crypto tests are trusted only after they have been seen to fail.** Mutate a KAT vector or label, paste WHICH assertion failed, revert.
- **Bindings drift is an instrument problem:** after `build-ios.sh`/`build-android.sh`, grep the regenerated header for every new symbol — count them.
- **Design before code** = the spec/decision note changes before the primitive; a wire-format change is a coordinated migration, never a refactor.

## Graphify & keep shared docs in sync

This repo has a knowledge graph at graphify-out/. Read `graphify-out/GRAPH_REPORT.md` before exploring code; run `graphify update .` after modifying code and commit; `graphify query "<question>"`; `graphify path "<A>" "<B>"`. When you add/change/remove endpoints, types, build commands, or dependencies: update the matching skill file in the workspace `.claude/skills/` directory (beebeeb-api.md, beebeeb-designs.md, beebeeb-stack.md, beebeeb-dev.md). Other agents depend on these being accurate.

## Task history

Pre-distillation CLAUDE.md verbatim (chunk-format v2 review rounds 1–5 + public API change list, onboarding review rounds, count-history baselines): docs/runbook/core-task-history.md

L7 (2237c): folder child key wraps authenticate `beebeeb-folder-child-v1 || shared root UUID bytes (16) || item UUID bytes (16) || kind (1=file, 2=folder)` under the random folder key, without HKDF or an unbound fallback. UniFFI accepts UUID strings and handles; WASM follows its existing byte-key API. Passphrase NFC uses fallibly preallocated zeroizing scalar scratch and UTF-8 output; normalization never grows an unwiped secret buffer.
