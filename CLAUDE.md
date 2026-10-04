# beebeeb-io/core

Cryptographic core, shared types, and sync engine. This is the trust anchor — every client depends on this.

## Crates

- `beebeeb-core` — AES-256-GCM encryption, Argon2id KDF (256MiB/4iter/2par), BIP39 recovery phrases, HKDF per-file key derivation, onboarding (password policy evaluator, breach-check helper, signup ceremony state machine)
- `beebeeb-types` — CipherSuite, EncryptedBlob, KdfParams, ChunkMeta (shared across all repos)
- `beebeeb-sync` — Desktop sync engine: file watcher (notify), conflict resolution (KeepBoth default), selective sync

## Build & test

```sh
cargo test -p beebeeb-core   # 405 tests across 9 binaries (unit 332, chunk_stream_parity 2, cli_auth_vectors 4 + 1 ignored, cross_client_vectors 21, cross_platform_vectors 22, integration 13, transfer_vectors 5, zip_tests 6) — measured 2026-10-04 on feat/1744-onboarding-module (base d18b336; baseline before the onboarding module was 358 = unit 285 + the same eight other binaries); the truth line is per binary: `test result: ok. N passed`
cargo test --workspace       # full workspace (core + sync + types + upload + uniffi + wasm)
cargo clippy --workspace -- -D warnings
cargo fmt -- --check
```

## Key types

- `MasterKey` — 32 bytes, NOT Clone, zeroized on drop. Created from password (Argon2id) or recovery phrase.
- `FileKey` — 32 bytes, per-file via HKDF. `derive_file_key(master_key, file_id)`.
- `EncryptedBlob` — cipher_suite + nonce (Vec<u8>) + ciphertext (Vec<u8>).
- `encrypt_chunk(key: &FileKey, plaintext)` / `decrypt_chunk(key: &FileKey, blob)` — AES-256-GCM.

## Streaming chunk primitive (`chunk_stream.rs`)

`chunk_stream::ChunkEncryptor` / `ChunkDecryptor` are the ONE shared chunk
encrypt/decrypt loop for every client (cli, desktop, mobile/UniFFI, web/WASM) —
no client re-implements the chunk loop. Generic-free (the reader is boxed behind
a private `Source`/`DecSource` enum) so the types cross UniFFI, and `Send` so the
CLI can move them into `spawn_blocking`. Core stays synchronous — no tokio.

- **Pull** (native): `ChunkEncryptor::from_reader(mk, file_id, file_size, profile, reader)`
  pulls one chunk at a time into a reused `Zeroizing` buffer (peak memory ≈ one
  chunk, never file-size-proportional). `next_chunk()` is plan-driven and returns
  `Ok(None)` once after the last chunk.
- **Push** (WASM, caller slices): `for_push` / `for_push_with_chunk_size` +
  `push_chunk`. `ChunkDecryptor::for_push` + `push_frame` mirror it.
  `for_push_with_chunk_size` lets a v2 server dictate the chunk size.
- The single crypto point is the private `encrypt_next` → `encrypt_chunk_raw`.
  `file_key` is derived ONCE in the constructor and is `ZeroizeOnDrop`.
- **Explicit chunk-size cap (`MAX_CHUNK_SIZE = 256 MiB`):** both
  `*_with_chunk_size` constructors reject `chunk_size_bytes` above the top of the
  profile ladder (256 MiB) via `check_explicit_chunk_size`, so a hostile/
  misconfigured server-dictated size can't drive a multi-GB allocation → client
  OOM. The WASM `withChunkSize` inherits this (it delegates to the core
  constructor). Resilience fix R3.
- `finish()` integrity guard: requires `emitted == chunk_count` AND
  `running_ciphertext == file_size + 28*chunk_count`. This **detects a source
  that SHRANK** mid-stream. It provably **cannot detect a source that GREW** when
  `file_size` is an exact multiple of the chunk size (the loop stops at the
  original `chunk_count`) — so the **grow case is caught one level up** in
  `file_encrypt::encrypt_file_to_chunks`, which **re-stats the input after
  `finish()`** and returns `Err` (cleaning up the chunk files it wrote) if the
  size diverged from the value the plan was built on. Resilience fix R1/R6 — a
  silent truncation is now a detectable, return-typed error across every client.
- **Wire format UNCHANGED:** `nonce(12) || ciphertext || tag(16)`, fresh random
  nonce per chunk. Output is roundtrip-compatible with existing files but NOT
  byte-identical (random nonce) — intentional. `vectors.json` stays v2.
- `file_encrypt::encrypt_file_to_chunks` now **DELEGATES** to `ChunkEncryptor`
  (one encrypt loop, no drift); `tests/chunk_stream_parity.rs` enforces an
  identical chunk plan + that new output decrypts via the legacy `decrypt_chunk_raw`.
- `NONCE_LEN` / `TAG_LEN` (defined in `encrypt`) and `read_exact_or_eof` (defined
  in `chunk_stream`) are `pub(crate)` — a single definition shared by the
  `encrypt` / `file_encrypt` / `chunk_stream` cluster (no duplication).
- The three legacy decrypt functions — `encrypt::decrypt_chunks_to_file`,
  `encrypt::decrypt_contiguous_to_file`, `file_encrypt::decrypt_chunks_to_file` —
  are the disk/legacy paths and are **NOT superseded** by `ChunkDecryptor` this
  round (a later cleanup may route them through it). **All three are now fully
  atomic** (crypto-hygiene follow-up to R2): each writes plaintext to a sibling
  `.tmp`, `rename`s onto the final path **only on full success**, and removes the
  `.tmp` on **any** error — including a mid-stream decrypt failure — so no partial
  plaintext ever survives at `output_path` and an existence-based cache cannot
  serve a truncated decrypt as if complete. `encrypt::decrypt_contiguous_to_file`
  gained this in resilience fix R2 (`decrypt_contiguous_to_tmp` helper);
  `file_encrypt::decrypt_chunks_to_file` (`decrypt_chunks_to_tmp` helper) and
  `encrypt::decrypt_chunks_to_file` (`decrypt_chunks_to_tmp` helper) gained it in
  the crypto-hygiene round. No signature change to any of them (UniFFI exports
  unchanged: `Result<u64>` / `DecryptedFileResult`). Each has a
  `..._leaves_no_partial_file_on_midstream_failure` test asserting neither the
  output file nor the `.tmp` survives a failed decrypt.
- **WASM binding (`beebeeb-wasm`):** `WasmChunkEncryptor` wraps the **push** form
  for the web client (single-threaded WASM can't `Read` a browser `File`, so JS
  slices the `Blob`). Constructor `new(master_key, file_id, file_size, profile)`
  (ladder plan) or static `withChunkSize(...)` (server-dictated size);
  `pushChunk(plaintext) -> Uint8Array` returns the full `nonce||ct||tag` frame
  (no JS recombine); consuming `finish()` runs the integrity guard. Getters:
  `chunkCount` / `chunkSize` / `chunksEmitted` / `expectedTotalCiphertext`. It is
  the first stateful `#[wasm_bindgen]` struct in the crate.

### WASM target gating (0653)

`beebeeb-core` builds for `wasm32-unknown-unknown` (so `beebeeb-wasm` builds in
place). `rusqlite` (bundled C SQLite, used only by `fp_cache`'s native
FileProvider cache) cannot target wasm32, so it is gated to non-wasm:
`rusqlite` lives under `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`
in `beebeeb-core/Cargo.toml`, and `pub mod fp_cache;` carries
`#[cfg(not(target_arch = "wasm32"))]`. Native (cli/server/desktop/uniffi/iOS)
builds are unaffected — the gate excludes wasm only. WASM JsValue returns
(`plan_chunks`, `WasmChunkEncryptor::finish`) serialize via typed `#[derive(Serialize)]`
structs so they cross as plain JS objects, not `Map`s (0655).

### UniFFI handles (`beebeeb-uniffi`) — mobile/desktop

`ChunkEncryptorHandle` / `ChunkDecryptorHandle` wrap the primitive for Swift/Kotlin
so mobile/desktop drop their bespoke encrypt loops:

- Each is a `#[uniffi::Object]` holding `Mutex<Option<ChunkEncryptor/Decryptor>>`.
  Constructors: encryptor `from_file` (pull, stats the file) + `for_push`; decryptor
  `from_file` (pull) + `for_push`. Methods `next_chunk` → `Result<Option<Dto>>`,
  `push_chunk`/`push_frame` → `Result<Dto>`, plus `chunk_plan`/`expected_total_ciphertext`/
  `chunks_emitted`; `finish()` `take()`s the `Option` (consume-by-value) so the handle
  is unusable afterwards. DTOs: `EncryptedChunkDto`/`DecryptedChunkDto` (`index: u32`,
  `data: Vec<u8>`), `ChunkEncryptorSummaryDto`.
- The key is derived IN CORE from a borrowed `&MasterKeyHandle` (`with_key`); raw key
  bytes never cross FFI.
- **Single-consumer contract:** a handle is an ordered cursor — drive it from ONE
  sequence. The `Mutex` is only the `Send + Sync` backstop UniFFI requires, not a
  concurrency primitive. There is deliberately NO UniFFI callback inside these handles
  (avoids a reentrant lock; contrast `MasterKeyHandle::encrypt_file`).
- Regenerating Swift/Kotlin bindings: run `build-ios.sh` (regens `beebeeb_uniffiFFI.h`
  + `BeebeebCore.swift` + xcframework) / `build-android.sh`. Grep the regenerated header
  for the new symbols before shipping (the 0426 12-symbol drift lesson).

## Encrypted search index (`search_index.rs`)

The shared, client-built, E2E-encrypted file-name search primitive (task 0778 part B).
The server is zero-knowledge — names are ciphertext there — so the index is built and
queried **on-device** in core, identically for every client (WASM/web, UniFFI/mobile,
CLI/desktop). No plaintext token or name ever leaves the device.

- **`tokenize(name) -> Tokenized`**: lowercase + Unicode NFKD + strip combining marks
  (accent-fold, e.g. `Café` → `cafe`), split on separators (space `_` `-` `.`) and
  camelCase boundaries, de-dup preserving order. Keeps the full normalized name for the
  substring fallback (so `"nf"` matches `NF_song.mp3` and `"ong"` matches `song.mp3`).
- **`SearchIndex`**: `build(&[(file_id, name)], num_shards)`, incremental `upsert(file_id, name)`
  / `remove(file_id)` (both return the **dirty bucket set** — re-encrypt only those), and
  `query(term) -> BTreeSet<file_id>` (exact + prefix + substring; flat over the whole vault,
  so a term in a deeply nested folder is still found).
- **Sharding**: deterministic `bucket = blake3(key)[..8] % num_shards` (`DEFAULT_NUM_SHARDS = 64`)
  for both tokens and file_ids; each bucket serializes to one or more **pages ≤ 128 KB after
  encryption** (a hot token splits across pages; loader unions them). `num_shards` is fixed
  per index — changing it needs a full rebuild.
- **Encryption**: per-shard key via `kdf::derive_search_index_key(master_key, bucket)` —
  HKDF-SHA256 with a domain-separation label (`beebeeb-search-index-shard-v1`) **distinct**
  from the per-file key label. `encrypt_shards` / `encrypt_buckets(dirty)` →
  `Vec<EncryptedShard{bucket, page, blob}>` where `blob = nonce||ciphertext||tag` (reuses the
  `encrypt_chunk_raw` AES-256-GCM primitive); `from_encrypted_shards` rebuilds.
- **Client bindings (task 0784).** Exposed through both surfaces — bindings only, the
  algorithm/crypto above are unchanged:
  - **UniFFI** (`beebeeb-uniffi`): `SearchIndexHandle` (`#[uniffi::Object]`, `Mutex<SearchIndex>`)
    with `new`/`build`/`from_encrypted_shards` constructors + `upsert`/`remove` (→ dirty buckets
    `Vec<u32>`) / `query` (→ `Vec<String>`) / `encrypt_shards` / `encrypt_buckets` / `num_shards`
    / `file_count`. Records `SearchFileEntry`, `EncryptedShardDto{bucket,page,blob}`. The master
    key is borrowed as `&MasterKeyHandle` (raw bytes never cross FFI). Regenerate Swift/Kotlin via
    `build-ios.sh` / `build-android.sh` (the committed `bindings/kotlin/...kt` + the Swift/xcframework
    artifacts) — run in the canonical toolchain so ktlint/uniffi versions match.
  - **WASM** (`beebeeb-wasm`): `WasmSearchIndex` (same surface; master key as 32 raw bytes,
    `EncryptedShard` ↔ `{bucket,page,blob:Uint8Array}` JS objects, `query` → `string[]`).
  - **Sync helper** (`search_sync::diff_manifest`, also exposed as UniFFI `searchIndexSyncPlan` /
    WASM `searchIndexSyncPlan`): pure manifest-diff → `{to_put,to_get,to_delete}` shard coords (LWW).
- **Client wiring status**: **WEB is wired (B4, task 0871)** — the web client builds on unlock,
  syncs shards via `/api/v1/search-index/shards`, and queries through `WasmSearchIndex`
  (`repos/web/src/lib/search-index-{core,shards,context}.tsx`); KAT-verified byte-identical to
  core. **Out of scope (follow-ups)**: MOBILE wiring (UniFFI `SearchIndexHandle` is built but not
  yet surfaced in `BeebeebCrypto.ts` — device-gated follow-up onto the SAME contract); retiring
  the old single-blob `/api/v1/index` (Guus-gated, only after BOTH web + mobile cut over); Part A
  recursive in-app search (ts-clients).
- Adds one dependency: `unicode-normalization` (pure-Rust, wasm-safe) for NFKD.

## CLI login handshake (`cli_auth.rs`)

The crypto behind `bb login`'s browser **device-authorization** flow (task 0861) —
moved out of the CLI so the handshake is no longer per-client. **Separate from
OPAQUE**: OPAQUE (`opaque_protocol.rs`) is the password login (web/mobile, server is
a crypto participant); this is how a `bb` CLI receives an *already-logged-in browser's*
`{session_token, master_key, email}`. The server (`server/.../cli_auth.rs`) is a blind
relay — it does no crypto.

- **Curve/KDF/AEAD:** P-256 ECDH (`raw_secret_bytes()` = 32-byte X) → HKDF-SHA256
  (salt=None, info `beebeeb-cli-auth-v1`) → AES-256-GCM (caller-supplied 12-byte nonce).
  Byte-identical to the web client's inline WebCrypto (`web/src/pages/cli-auth.tsx`).
- `CliEphemeralKey::generate()` (prod, OsRng) / `from_secret_bytes()` (deterministic
  vectors); `shared_secret()` / `decrypt_browser_payload()`. Shared secret + derived key
  are `Zeroizing<[u8;32]>`. The struct deliberately does NOT derive `Debug` (no key leak).
- `decrypt_cli_payload()` tries the HKDF key, then falls back to the **raw shared secret**
  as the AES key (legacy v0.4 web app) — both authenticated GCM decrypts.
- Adds dep `p256` (features `["ecdh"]`). The CLI dropped its own p256/aes-gcm/hkdf deps.
- **Wire format is pinned, no protocol change:** `tests/cli_auth_vectors.rs` (ECDH→HKDF
  drift tripwire) + `cli/tests/ecdh_compat.rs` (a real Node.js WebCrypto vector proving
  core == browser byte-for-byte). Changing the info string / point encoding breaks live
  `bb login` — it is a coordinated cross-client migration, never a refactor.

## Onboarding module (`onboarding/`) — task 1744

The logic every client must run identically during signup, driven by numbers the
server declares in the backend-driven onboarding document
(`docs/specs/2026-10-04-backend-driven-onboarding.md` in the workspace, sections 5.5
and 5.12). **No new cryptographic primitive:** the ceremony is a state machine over
the existing `recovery::generate_recovery_phrase`, `opaque_protocol::client_registration_*`
and `opaque::{derive_x25519_private, derive_x25519_public, compute_recovery_check}`.
No I/O (core stays synchronous and WASM-clean). The one dependency added is `sha1`,
only to address the breach corpus (it is the corpus' key), never for integrity.

- **`onboarding::password`** — `PasswordPolicy::from_server(min_length)` +
  `evaluate_password(&str, &PasswordPolicy) -> PasswordEvaluation` (length, `meets_minimum`,
  `missing_characters`, `PasswordStrength` TooShort/Fair/Good/Strong = meter level 1 to 4,
  `PasswordHint`). Ports the web heuristic (length gate, then mixed case, then number or
  symbol). Copy stays in clients. Differences from the TypeScript it replaces: length is
  Unicode scalar values (JS counted UTF-16 units) and case/symbol detection is Unicode aware.
  `MIN_LENGTH_FLOOR = 12` (lead decision 2026-10-04, review L5) is a **floor** applied inside
  `from_server`, not the policy: the server may raise the number, never lower it below the 12
  the product ships with, so a hostile onboarding document cannot weaken what clients enforce.
  There is deliberately no hard-coded fallback policy. The evaluator is advisory UX plus a
  client-side gate, not a guessing-cost estimator: whitespace-only or repeated-character strings
  that meet the length score Fair or Good (the web heuristic, unchanged); the breach check is
  the backstop (review L6).
- **`onboarding::breach`** — k-anonymity helper, hashing and matching only.
  `BreachQuery::from_password` (SHA-1, upper-case hex, 5-char `prefix()` to send, 35-char
  `suffix()` that never leaves the device; zeroized on drop), then
  `evaluate_breach_response(&query, BreachResponse::Body(text) | Unavailable, fail_open)
  -> BreachVerdict` (`Clean`, `Breached{count}`, `CheckFailedAllowed`, `CheckFailedBlocked`,
  `NotRequired`) for display. **`BreachCheck`** is what the ceremony accepts: a query bound to
  its password plus the recorded answer (`new(password)`, `prefix()`, `record(response)`,
  `verdict(fail_open)`, `matches_password(pw)`). **The HTTP call stays in each client and goes
  to Beebeeb's own endpoint** (server `GET /api/v1/auth/pwned-range/{prefix}`, node-local
  corpus; the onboarding document declares it as `policy.password.breach_check.endpoint`).
  The helper names no third-party service: the public HaveIBeenPwned API is behind a US CDN
  and violates the no-US-systems rule (task 0995). Outage policy: transport failure, non-2xx,
  an **empty or whitespace-only body**, a body over `MAX_BODY_BYTES` (256 KiB; clients stop
  reading there), or any line that is not `SUFFIX[:COUNT]` is an outage (a captive-portal page
  returned as 200 must not read as clean); `fail_open` (from the document) picks
  `CheckFailedAllowed` vs `CheckFailedBlocked`. Why empty is an outage (review M2): the server
  route answers `200` + empty body for an unseeded corpus, a failed corpus read, AND an absent
  prefix (`routes/auth.rs::pwned_range` unwraps all three), and a seeded corpus never has an
  empty block, so empty means "not consulted". Count 0 is range padding and means not present.
  Known limit (review L1): `sha1` 0.10 cannot be zeroized, so the hasher's block buffer (up to
  63 password bytes) is freed unwiped; the digest and hex are wiped.
- **`onboarding::ceremony`** — `SignupCeremony`, one per signup attempt. Steps (canonical
  order): `VerifyEmail` (only if the document requires it), `SetPassword`, `SavePhrase`,
  `ConfirmPhrase`, `CreateAccount`, `Done`; `spec_step_id()` maps the two phrase parts to the
  server's single `save_recovery_phrase`. **Only `create_account` is gated**: it refuses
  (`StepNotDone`) until every other required step is done. The relative order of
  `set_password` and the phrase steps is deliberately not enforced (the shipped web client
  shows the phrase first; the spec's example document lists the password first; the server's
  `steps` array orders the UI). Flow: `email_verified()`, `set_password(pw, confirmation,
  Option<&BreachCheck>)`, `begin_phrase()` (Argon2id, about 1 s, idempotent), `phrase()`,
  `acknowledge_phrase()`, `challenge_positions()` (1-based, stable, count from
  `policy.recovery_phrase.verify_word_count`, floored at `VERIFY_WORD_COUNT_FLOOR = 3`),
  `confirm_phrase(answers)`, `start_registration()` -> OPAQUE request,
  `finish_registration(server_message)` -> `{upload, x25519_public, recovery_check}`,
  `account_created()` -> the `MasterKey`. Recovery paths: `registration_failed()` (retry with
  a fresh OPAQUE exchange), `email_ticket_invalidated()` (back to the code step, spec 5.9) and
  `email_changed()` (the user edited the verified email: verification withdrawn, secrets kept).
  **The breach gate is enforced here, once** (review M1, Codex P1): `CeremonyConfig.breach` is
  `BreachPolicy::NotRequired | Required { fail_open }` from the document. When required,
  `set_password` demands a `BreachCheck`, re-derives the digest from the password it stores and
  refuses a check made for another password (`BreachCheckStale`, code `breach_check_stale`) or
  one with no recorded answer (`BreachCheckMissing`, `breach_check_missing`), then computes the
  verdict itself with the document's `fail_open`. A bare verdict is not accepted anywhere, so a
  stale or forged "clean" cannot pass, and a client cannot pick `fail_open`. The ceremony has no
  notion of the email address: the server's signup-ticket binding is what ties a verified email
  to the created account and is mandatory server side.
  Memory: password and phrase are `Zeroizing`; the phrase string is wiped the moment it is
  confirmed, the master key derived from it and the password are kept until
  `account_created()` so a rejected `register-finish` does not force a different phrase on the
  user; dropping the ceremony wipes everything, **but a binding handle is freed on the host's
  schedule (JS finalizer, ARC, GC), so clients must call `wipe()` (`abandon()` in the bindings)
  on back, cancel and error exits** (review M3). `wipe()` returns the ceremony to a fresh state
  with the same config. The `phrase()` copy handed to a UI cannot be wiped by Rust (review L4):
  call it only while rendering and drop the reference.
- **Bindings.** WASM (`beebeeb-wasm`): free fn `evaluate_password(password, min_length)`;
  `WasmBreachCheck` (`new(password)`, `prefix`, `evaluate(body|null, failOpen)` which records the
  answer and returns the display verdict); `WasmSignupCeremony(minLength, emailVerificationRequired,
  verifyWordCount, breachCheckRequired, breachFailOpen)` (camelCase methods mirroring the list
  above, plus `abandon()` and `emailChanged()`; `setPassword(password, confirmation,
  breachCheck)` borrows the `WasmBreachCheck` object, not a verdict, and
  `setPasswordUnchecked(password, confirmation)` is for documents with no breach check (it
  throws `breach_check_missing` when the ceremony was built with `breachCheckRequired`);
  `accountCreated()` copies the key through a `Zeroizing` temporary into a
  `Uint8Array`, so no plain Rust-side copy outlives the call). Enum-like values cross as lowercase string
  tokens (`as_str()` in core), objects are plain JS objects (typed `Serialize` structs, 0655),
  counts are `f64`, ceremony errors are thrown `Error`s with a stable `code`
  (`CeremonyError::code`). The verdict object `evaluate` returns is output only; nothing a JS
  caller builds by hand can satisfy the gate.
  UniFFI (`beebeeb-uniffi`): `evaluate_password`, `breach_verdict_allows_proceeding`,
  `breach_verdict_check_failed`, `ceremony_step_spec_id`, handles `BreachCheckHandle` and
  `SignupCeremonyHandle(min_length, email_verification_required, verify_word_count,
  breach_check_required, breach_fail_open)` (`set_password(password, confirmation,
  Option<BreachCheckHandle>)`, `abandon()`, `email_changed()`; `account_created()` returns a
  `MasterKeyHandle`, so the key does not cross FFI as bytes on this path. The handle is not a
  sandbox: it still offers `export_for_keychain()` and `derive_x25519_private()` for keychain
  storage, review L8. Owned `String` arguments are wrapped in `Zeroizing`; the handle lock
  recovers from poisoning), enums `PasswordStrengthDto`, `PasswordHintDto`, `BreachVerdictDto`,
  `CeremonyStepDto`, record `PasswordEvaluationDto`, `RegistrationFinishDto` (no `Debug`), and a separate
  `OnboardingError` (so the UI branches on cause, not on text). Swift: `evaluatePassword`,
  `BreachCheckHandle`, `SignupCeremonyHandle`, `OnboardingError`. The committed Swift
  bindings and header (`beebeeb-uniffi/bindings/`) were regenerated: 26 new `uniffi_beebeeb_uniffi_fn_*`
  symbols, no existing declaration lost. The committed Kotlin file is stale for reasons
  unrelated to this task and was not touched (`build-android.sh` regenerates it).
- **Tests are trusted only after mutation:** weakening the length check fails
  `min_length_is_enforced_at_the_boundary`; flipping `fail_open` fails four breach tests;
  removing the floor fails `floor_clamps_a_hostile_server_value`; ignoring the
  `ConfirmPhrase` prerequisite fails `create_account_is_refused_until_every_prerequisite_is_done`.
  Round 2 (review): ignoring the password binding fails
  `a_breach_check_for_another_password_is_refused`; an empty body read as clean fails
  `empty_body_is_an_outage_not_clean`; a no-op `wipe()` fails
  `wipe_abandons_everything_and_the_ceremony_starts_over`.

## Security invariants

- MasterKey and FileKey are NOT Clone — prevents accidental key copies in memory
- All intermediate key buffers use `Zeroizing<[u8; 32]>` — zeroed on drop
- Each file gets its own key via HKDF(master_key, file_id) — limits blast radius
- Recovery phrase IS the master secret — password wraps it, doesn't replace it
- No panics in crypto paths — everything returns Result

## Design references

Design files are in the workspace root: `../../design/hifi/` — never copy them into this
public repo. A snapshot that lived here until 2026-09-25 published a false external-audit
claim (firm + date) and Digital Operational Resilience Act copy; the `Claims guard` CI job
(`scripts/claims-guard/canon-sweep.sh`) now fails on those strings anywhere in the tree.

## Claims guard

- `bash scripts/claims-guard/claims-guard.sh` — shared engine + `policy.conf`, vendored verbatim
  from the workspace `scripts/claims-guard/` (do not edit the copies here; edit the workspace
  canonical and re-copy). Reviewed exceptions: `.claims-allow` (`path|token|evidence`).
- `bash scripts/claims-guard/canon-sweep.sh` — the canon CLAIM_SWEEP from
  `docs/canon/public-claims.md` over the WHOLE tree; must print `clean (0 rows)`.
  `--self-test` proves it goes red on a throwaway repo.

## License

AGPL-3.0-or-later


## How we work (evidence, design, done, parallel agents)

The full rules live in the workspace `CLAUDE.md` → "How we work" (also summarised in the workspace `AGENTS.md`). Read them; they apply here. The repo-specific instantiation:

- **The count-shaped truth line:** `cargo test --workspace 2>&1 | tee /tmp/bb-core-test.log` →
  one `test result: ok. N passed; 0 failed` per crate/suite (the CLAUDE.md numbers above — 405 across
  9 binaries for `beebeeb-core`, measured 2026-10-04 (358 before task 1744) — are the baseline to compare against). Assert the Ns; a suite that did not run is
  a red, not a pass.
- **Crypto tests are trusted only after they have been seen to fail.** Mutate a KAT vector or a
  derivation label, paste WHICH assertion failed, revert. A KAT that cannot fail proves nothing.
- **Bindings drift is an instrument problem:** after `build-ios.sh` / `build-android.sh`, grep the
  regenerated header for every new symbol before shipping (the 0426 12-symbol lesson) — count them.
- **Design before code** here means the spec/decision note (`docs/`, the cross-client KDF context
  notes) changes before the primitive; a wire-format change is a coordinated migration, never a refactor.

## Graphify

This repo has a knowledge graph at graphify-out/.
- Before exploring code, read graphify-out/GRAPH_REPORT.md for module structure and relationships
- After modifying code, run `graphify update .` and commit the updated graphify-out/
- The graph tracks modules, functions, types, and their relationships (calls, imports, inherits)
- Use `graphify query "<question>"` to ask questions about the codebase
- Use `graphify path "<A>" "<B>"` to find connections between two concepts

## Keep shared docs in sync

When you add/change/remove endpoints, types, build commands, or dependencies: update the matching skill file in the beebeeb workspace's `.claude/skills/` directory (beebeeb-api.md, beebeeb-designs.md, beebeeb-stack.md, beebeeb-dev.md). Other agents depend on these being accurate.
