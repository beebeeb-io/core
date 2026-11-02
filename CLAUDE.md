# beebeeb-io/core

Cryptographic core, shared types and sync engine (PUBLIC repo). This is the trust anchor: every client depends on it. License AGPL-3.0-or-later.
Moved detail (key types, chunk format v2, adoption checklist, UniFFI/WASM handles, folder links, owner file keys, client metadata, search index,
CLI handshake, onboarding, direct S3 transfer, L2 driver, security invariants, L16 labels): `docs/agent-notes.md`.
Pre-distillation CLAUDE.md verbatim (chunk-format v2 review rounds, count-history baselines): `docs/runbook/core-task-history.md`.

## Commands

```sh
cargo test -p beebeeb-core      # unit + suite binaries (chunk_stream_parity, cli_auth_vectors, cross_client_vectors, cross_platform_vectors,
                                # direct_transfer_authority, integration, transfer_vectors, zip_tests, l16_labels, ...) + doctests
cargo test --workspace 2>&1 | tee /tmp/bb-core-test.log        # full workspace
cargo clippy --workspace -- -D warnings; cargo fmt -- --check
wasm-pack build beebeeb-wasm --target web                      # then `make wasm-sync` from the workspace root (committed package in repos/web)
./build-ios.sh / ./build-android.sh                            # UniFFI bindings; BUILDING.md
bash scripts/claims-guard/claims-guard.sh                      # shared engine + policy.conf, vendored verbatim from the workspace; exceptions in .claims-allow
bash scripts/claims-guard/canon-sweep.sh                       # must print `clean (0 rows)`; --self-test proves it goes red
```

Truth line: one `test result: ok. N passed; 0 failed` per crate/suite; assert the Ns, a suite that did not run is a RED. Crypto tests are trusted only
after they have been seen to fail: mutate a KAT vector or label, paste WHICH assertion failed, revert. Bindings drift is an instrument problem: after
`build-ios.sh`/`build-android.sh`, grep the regenerated header for every new symbol and count them.

## Module map

```
beebeeb-core/   AES-256-GCM, Argon2id KDF (256MiB/4iter/2par), BIP39 recovery, HKDF per-file keys, onboarding state machine
  src/kdf.rs, encrypt.rs, file_encrypt.rs   key derivation and the label table (label_table_tests.rs lists every HKDF info/AAD/salt label)
  src/chunk_stream.rs        ChunkEncryptor / ChunkDecryptor: the ONE chunk encrypt/decrypt loop for every client; chunk format v1/v2 (position binding)
  src/owned_keys.rs, item_id.rs, folder_key.rs   owner file-key wraps (L8), item id classes (F/O), folder key id
  src/client_meta.rs, search_index.rs, search_sync.rs, cli_auth.rs, file_request.rs, share_token.rs   encrypted client metadata, search, CLI handshake, requests
  src/direct_transfer/       pure-Rust rules of the direct S3 transfer contract (no I/O, clock or runtime); vectors in test-vectors/direct_transfer.json
  src/onboarding/            password policy, breach (k-anonymity) check, signup ceremony; src/opaque*.rs, recovery.rs
beebeeb-types/  CipherSuite, EncryptedBlob, KdfParams, ChunkMeta (shared across all repos)
beebeeb-sync/   desktop sync engine: watcher (notify), conflicts (KeepBoth), selective sync
beebeeb-transfer/  L2 driver above direct_transfer: one download() over any DirectIo (CLI + desktop)
beebeeb-upload/, beebeeb-wasm/ (web; js-tests/), beebeeb-uniffi/ (mobile/desktop handles)   bindings/
test-vectors/vectors.json + direct_*.json + tools/ (independent Python generators)   drift guards: test_vectors_v2, published_v2_vectors_match_core
```

## Traps

- **`MasterKey` and `FileKey` are NOT Clone;** all intermediate key buffers are `Zeroizing`; no panics in crypto paths (everything returns `Result`). The recovery phrase IS the master secret.
- **Generic `encrypt_chunk`/`decrypt_chunk` (no AAD) is NOT for file content, names, thumbnails or notes:** content goes through `chunk_stream`; names/thumbnails/notes
  through their purpose subkeys (`encrypt_name*`, `encrypt_thumbnail[_for]`, `encrypt_note[_for]`). Never seal a name/thumbnail/note under the raw per-file key.
- **A wire-format change is a coordinated migration, never a refactor.** A new derivation gets a new info string (`v2`); never change an existing one. Every HKDF info/AAD/salt label
  is listed in `label_table_tests.rs` and distinct. New vectors need an independent generator (Python) and the drift guards.
- **Chunk format:** v1 frames have no AAD; v2 binds position (STREAM). New files are written as v1 during the rollout (`WRITE_FORMAT`, task 1908); every reader reads both.
  Every content reader REQUIRES the pin (`ExpectedChunkFormat` from `decrypt_file_metadata[_with_key]`, never a server value); `V2` only from an EXISTING file's authenticated
  metadata, never for a NEW file. `finish()` is the integrity guard: call it and DISCARD all plaintext on any `Err`. Adoption checklist: `docs/agent-notes.md` → "Chunk format v2".
- **Resume:** `resume_policy(stored, writing)` continues a session ONLY for `(V1Legacy, V1Legacy)`; otherwise abandon and restart from chunk 0 in a new session, never PUT into the old one.
- **`MAX_CHUNK_SIZE` = 256 MiB** rejects a hostile server-dictated size (client OOM guard). Legacy decrypt paths write a sibling `.tmp` and rename on full success only.
- **Folder keys are random** (OS CSPRNG), never derived from the master key; a link passphrase KDF error propagates, clients never downgrade to an unprotected link.
- **Raw key bytes never cross FFI** (UniFFI handles; single-consumer cursors). WASM returns typed `Serialize` structs, not `Map`s; `rusqlite` (`fp_cache`) is gated to non-wasm.
- **Breach check:** the HTTP call stays in each client and goes to Beebeeb's own `/api/v1/auth/pwned-range/{prefix}`, never the HIBP API (no US systems, task 0995);
  `MIN_LENGTH_FLOOR = 12` (a server may raise, never lower); clients call `wipe()`/`abandon()` on back, cancel and error exits.
- **Direct transfer:** `X-Beebeeb-Capabilities` goes on grant/init requests ONLY; no event, error or `Debug` string may carry a URL (`redact`/`scrub`); each client keeps its own HTTP stack.
- **Search index:** `DEFAULT_NUM_SHARDS = 64` (WASM accepts at most 64); the shard key label is `beebeeb-search-index-shard-v1`.
- **Design files live in the workspace `../../design/hifi/`; never copy them into this public repo** (a snapshot once published a false external-audit claim; the Claims guard fails on those strings).

## How we work

Workspace `CLAUDE.md` → "How we work" is the rule set (evidence, design before code, done, parallel agents). Here: the truth lines above; design before code means the
spec or decision note changes before the primitive. Clients adopt core changes by bumping their pin (server `CORE_REV`, cli `rev`, web WASM via `make wasm-sync`).

## Graphify and shared docs

Knowledge graph at `graphify-out/`. Architecture question: `graphify query "<question>"` / `graphify explain <symbol>` /
`graphify path "<A>" "<B>"`; overview: `graphify-out/GRAPH_SUMMARY.md` (at most 3k tokens); never read `GRAPH_REPORT.md` whole.
Run `graphify update .` for your own navigation; never commit `graphify-out/` on a feature branch (the lead regenerates it on main).
When you add/change/remove endpoints, types, build commands or dependencies, update the matching skill in the workspace `.claude/skills/`
(crypto primitives, key types and the encryption flow are documented in this repo's `docs/agent-notes.md`).
