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

## Encrypted search index (`search_index.rs`)

Client-built, E2E-encrypted file-name search; the server is zero-knowledge, everything runs on-device, identically for every client. `tokenize(name)`: NFKD + accent-fold + separators + camelCase, dedup preserving order; keeps the full normalized name for substring fallback.
- `SearchIndex`: `build`, incremental `upsert`/`remove` (return the dirty bucket set), `query` (exact + prefix + substring).
- Sharding: `bucket = blake3(key)[..8] % num_shards` (`DEFAULT_NUM_SHARDS = 64`), pages ≤ 128 KB after encryption; `num_shards` fixed per index.
- Encryption: per-shard key `kdf::derive_search_index_key` (HKDF label `beebeeb-search-index-shard-v1`, distinct from the file-key label); `blob = nonce||ciphertext||tag` via `encrypt_chunk_raw`.
- Bindings: UniFFI `SearchIndexHandle` + WASM `WasmSearchIndex` (same surface); sync helper `search_sync::diff_manifest` (`searchIndexSyncPlan`). Dependency: `unicode-normalization` (NFKD).
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

- `wire`: tokens `object-download-v1` / `object-upload-v1`; `X-Beebeeb-Capabilities` goes on grant/init requests ONLY, never globally; serde types. The upload types are frozen by the spec but not yet served: verify them against the real routes before a client sends them. Grant types `Debug`-print their URL without its query.
- `authority::check_storage_url`: a strict printable-ASCII grammar, so what was checked is what any URL parser connects to (https; a listed `{host, bucket}` in path style; no userinfo, IP-looking host, unlisted port or dot segment; http only to loopback when the API base is loopback http). `redact` / `scrub` are the only ways a URL, or text that may contain one, reaches a log, error or progress line.
- `classify`: R1.6. Only a JSON-bodied 404 (JSON content type AND an `error` string) is terminal; a bare/HTML 404, 405, 5xx or no answer means "no direct transport on this node". 409 `direct_unavailable` / `replace_in_progress` / unknown → API for this file; `version_unavailable` → restart; 429 → back off (Retry-After clamped 1–120 s); 401/403 → terminal. `Call::PinnedChunk` (`GET /files/{id}/chunks/{i}?object_version_id=`) is classified here too and differently: ANY 409 except `replace_in_progress`/`commit_in_progress` (a wait) is `Restart` — the server's body for a gone pin is a sentence, not a code, so the status is the contract; 429 → back off; 5xx / bare 404 / 405 / no answer → `Outcome::Retry` (a 5xx that sends `Retry-After`, as the server's 503 does, is a stated `Backoff` instead); 401/403/JSON 404 → terminal; other 4xx → the API stream. `PinnedRetry::decide` is the one retry policy (4 attempts, 150 s of waiting in all so the server's real `Retry-After: 60` 429 fits more than once, a stated wait kept, otherwise 1 s doubling) so no client hand-rolls it.
- `window::DownloadPlanner`: windows of grants (refill at ≤ 2 unused), ≤ 4 chunk requests in flight and no chunk further ahead than that (the decryptor is in-order), grants unused inside a 30 s margin, ≤ 3 renewals per chunk then the pinned API route, one API re-fetch of a chunk that fails authentication before `Verdict::Corrupt`. Every grant is checked against the response geometry and `check_storage_url` before the caller sees it. Time and jitter are injected. `DiscoveryCache` forgets everything after `DISCOVERY_TTL_MS` (a good answer, a JSON 404 `NotSupported`, and two failed attempts), so a long-lived client probes again after ten minutes instead of staying off the direct transport until it restarts.
- Bindings: `beebeeb-wasm` (`WasmDownloadPlanner`, `WasmDirectDiscoveryCache`, `checkStorageUrl`, `classifyDirectAnswer`, `parseDirectDiscovery`, `redactUrl`, `scrubText`, `directTransferConstants`, `directDownloadGrantsPath`) and `beebeeb-uniffi` (`DirectDownloadPlannerHandle`, `DirectDiscoveryCacheHandle`, `direct_*` functions) are thin type converters over this module; no rule lives in them. Enum-like values cross as the stable `code()` / `kind()` strings of the core types; failures carry a code and never a URL; the planner is a handle (one sequence's cursor, fed `now_ms` on every call). A wrapper that cannot run without a JS engine calls a plain-Rust seam the tests run; the JS-facing paths themselves (the module loads, `poll()` hands out a `WasmSignedUrl` whose `String()`/`JSON.stringify`/`util.inspect` never show the link, the seed through `Math.random()`) are run under node by `beebeeb-wasm/js-tests/run.sh` (builds BOTH `--target nodejs` and `--target web` into a temp dir, `node --check`s the glue, `tsc --noEmit`s the `.d.ts` files and runs `node --test`; needs wasm-pack, node >= 20 and tsc; CI job `wasm-js`). Never put a block-comment token (`/*` or `*/`) in a `///` doc comment of `beebeeb-wasm` or `beebeeb-uniffi`: it is copied into a JSDoc block in the generated glue and `.d.ts` (a closer ends the block early) and into Kotlin/Swift doc comments (an opener starts a nested one); the test `no_doc_comment_contains_a_block_comment_token` in each crate fails on it.
- Vectors: `test-vectors/direct_transfer.json` (hand-authored; authority, classify, redact, scrub, chunk-length and planner-scenario rows) is run by ONE interpreter, `direct_transfer::vectors` (`test-support`), through core, the WASM seams and the UniFFI exports. Each run asserts the per-section row COUNT equals the file's, so a skipped section is a failure, and `the_runner_goes_red_when_a_surface_drifts` proves the runner can fail. A rule change edits the file first; a client that disagrees fails its own binding test.
- Tests: the `direct_transfer::` unit tests and `tests/direct_transfer_authority.rs` (hostile-URL table; a differential fuzz against the `url` crate). Every rule has a recorded mutation that fails a named test (task 2173 notes); a new rule needs one.

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
