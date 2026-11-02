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
- **A wire-format change is a coordinated migration, never a refactor.** A new derivation gets a new info string (`v2`); never change an existing one. Every HKDF info/AAD/salt label
  is listed in `label_table_tests.rs` and distinct. New vectors need an independent generator (Python) and the drift guards.
- **Chunk format:** v1 frames have no AAD; v2 binds position (STREAM). New files are written as v1 during the rollout (`WRITE_FORMAT`, task 1908); every reader reads both.
  Every content reader REQUIRES the pin (`ExpectedChunkFormat` from `decrypt_file_metadata[_with_key]`, never a server value); `V2` only from an EXISTING file's authenticated
  metadata, never for a NEW file. `finish()` is the integrity guard: call it and DISCARD all plaintext on any `Err`. Adoption checklist: `docs/agent-notes.md` → "Chunk format v2".
- **Resume:** `resume_policy(stored, writing)` continues a session ONLY for `(V1Legacy, V1Legacy)`; otherwise abandon and restart from chunk 0 in a new session, never PUT into the old one.
- **`MAX_CHUNK_SIZE` = 256 MiB** rejects a hostile server-dictated size (client OOM guard). Legacy decrypt paths write a sibling `.tmp` and rename on full success only.
- **Search index:** `DEFAULT_NUM_SHARDS = 64` (WASM accepts at most 64); the shard key label is `beebeeb-search-index-shard-v1`.
- **Design files live in the workspace `../../design/hifi/`; never copy them into this public repo** (a snapshot once published a false external-audit claim; the Claims guard fails on those strings).

## Never break

The rules whose breakage costs data, a key, a credential or a user. One line each; the detail is in `docs/agent-notes.md`.

- `UpperRepair` rows: Core never writes under it and never migrates a row; a file is READ-ONLY if its name or ANY version reports it (SF-0002).
- Item ids: F ids are never derived (key from an L8 owner envelope or L7 child wrap); non-canonical id text is `InvalidInput`, never treated as an owner id.
- `folder_key_id` is not secret and must NEVER be used as a key; a new derivation gets a new info string (`v2`), never a change to this one.
- A client told to restart MUST first `POST /api/v1/files/{id}/upload/abandon`; never PUT into the old session again, never fall back to the old session.
- v2 frames never use the raw file key (key separation); `version_id` is frame 0's random 96-bit nonce.
- Writers record the format; never upgrade a file id with v1 history, never drop a recorded 2; unknown recorded values are errors, never fallback to detection.
- Generic no-AAD `encrypt_chunk`/`decrypt_chunk` stays for key wrap, search shards, v1 content, never to SEAL a name/thumbnail/note under a per-file key.
- Read the content pin with `decrypt_file_metadata[_with_key]` (never `decrypt_name_metadata`, never a server field) and pass `chunk_format` on.
- Take the chunk format from the pin, never from a server value; prefer `version_id()` over re-reading chunk 0's first 12 bytes.
- `V2` only from an EXISTING file's authenticated metadata; a NEW file never does (lead ruling 2026-10-17); each client tests its new-file path never passes `V2`.
- Notes: write with `encrypt_note_for(file_key, text, pin)`, read with `decrypt_note`; never `encrypt_metadata`/`encryptFilename`/`encrypt_chunk` for a note.
- UniFFI: raw key bytes never cross FFI. Single-consumer contract: a handle is an ordered cursor driven from ONE sequence.
- Folder keys are random (`FileKeyHandle.generate`, OS CSPRNG), never derived from the master key; `key_id` is the one-way folder-key id, never the key itself.
- Canonical ids are UTF-8. Never fall back to the legacy file-key custody opener after authentication fails (L6).
- Owner file-key wraps (L8) use the same textual encoding as L6 custody, never the binary UUID encoding of L7.
- `ClientMetaKey`: the derived key is never exported (a `FileKey` would also fit `encrypt_chunk`); `current_file`/`detail` are discarded from S1, never sealed.
- A wire-format, info-string or point-encoding change is a coordinated cross-client migration, never a refactor.
- `MIN_LENGTH_FLOOR = 12` is a floor applied inside `from_server` (the server may raise, never lower); no hard-coded fallback policy.
- Breach check: the SHA-1 suffix never leaves the device. The HTTP call stays in each client, to Beebeeb's own endpoint, never the public HIBP API (task 0995).
- `X-Beebeeb-Capabilities` goes on grant/init requests ONLY, never globally. A session's transport never changes after init, so there is no mid-session API chunk.
- Direct transfer failures carry a code and never a URL; the planner is a handle (one sequence's cursor).
- The presigned link is never a string past the binding: `WasmSignedUrl` and `DirectSignedUrl` print scheme and host only.
- Never retry into a sink that returned `DirectFailedAfterWrite`; after `UseApi` or any `Err` use a FRESH sink.
- Direct-transfer clients write `<path>.bbtmp` and rename, never stdout straight to the driver.
- Passphrase NFC normalization never grows an unwiped secret buffer; core never seals a name its own opener refuses (`kdf::sanitize_actor_name`).
- `kdf::open_legacy_child_key` refuses a 32-byte UTF-8 plaintext, so a name or label sealed under the same folder key can never be served as a child key.
- Direct vectors: add rows in the generator, never in the JSON (`check-direct-vectors-generated.sh` fails on hand edits).

## How we work

Workspace `CLAUDE.md` → "How we work" is the rule set (evidence, design before code, done, parallel agents). Here: the truth lines above; design before code means the
spec or decision note changes before the primitive. Clients adopt core changes by bumping their pin (server `CORE_REV`, cli `rev`, web WASM via `make wasm-sync`).

## Graphify and shared docs

Knowledge graph at `graphify-out/`. Architecture question: `graphify query "<question>"` / `graphify explain <symbol>` /
`graphify path "<A>" "<B>"`; overview: `graphify-out/GRAPH_SUMMARY.md` (at most 3k tokens); never read `GRAPH_REPORT.md` whole.
Run `graphify update .` for your own navigation; never commit `graphify-out/` on a feature branch (the lead regenerates it on main).
When you add/change/remove endpoints, types, build commands or dependencies, update the matching skill in the workspace `.claude/skills/`
(crypto primitives, key types and the encryption flow are documented in this repo's `docs/agent-notes.md`).
