# beebeeb-io/core

Cryptographic core, shared types, and sync engine. This is the trust anchor — every client depends on this.

## Crates

- `beebeeb-core` — AES-256-GCM encryption, Argon2id KDF (256MiB/4iter/2par), BIP39 recovery phrases, HKDF per-file key derivation
- `beebeeb-types` — CipherSuite, EncryptedBlob, KdfParams, ChunkMeta (shared across all repos)
- `beebeeb-sync` — Desktop sync engine: file watcher (notify), conflict resolution (KeepBoth default), selective sync

## Build & test

```sh
cargo test -p beebeeb-core   # 255 tests (8 suites), incl. the chunk_stream streaming primitive
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
- `finish()` integrity guard: requires `emitted == chunk_count` AND
  `running_ciphertext == file_size + 28*chunk_count`. This **detects a source
  that SHRANK** mid-stream; it provably **cannot detect a source that GREW** when
  `file_size` is an exact multiple of the chunk size (the loop stops at the
  original `chunk_count`) — documented on the method.
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
  round (a later cleanup may route them through it).
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
- **Out of scope (follow-ups)**: server `search_index_shards` storage + list-versions endpoint;
  WASM/UniFFI bindings + client query integration; Part A (recursive in-app search) is a
  separate ts-clients task.
- Adds one dependency: `unicode-normalization` (pure-Rust, wasm-safe) for NFKD.

## Security invariants

- MasterKey and FileKey are NOT Clone — prevents accidental key copies in memory
- All intermediate key buffers use `Zeroizing<[u8; 32]>` — zeroed on drop
- Each file gets its own key via HKDF(master_key, file_id) — limits blast radius
- Recovery phrase IS the master secret — password wraps it, doesn't replace it
- No panics in crypto paths — everything returns Result

## Design references

Design files are in the workspace root: `../../design/hifi/`

## License

AGPL-3.0-or-later


## Graphify

This repo has a knowledge graph at graphify-out/.
- Before exploring code, read graphify-out/GRAPH_REPORT.md for module structure and relationships
- After modifying code, run `graphify update .` and commit the updated graphify-out/
- The graph tracks modules, functions, types, and their relationships (calls, imports, inherits)
- Use `graphify query "<question>"` to ask questions about the codebase
- Use `graphify path "<A>" "<B>"` to find connections between two concepts

## Keep shared docs in sync

When you add/change/remove endpoints, types, build commands, or dependencies: update the relevant skill file in `/home/guus/code/beebeeb.io/.claude/skills/` (beebeeb-api.md, beebeeb-designs.md, beebeeb-stack.md, beebeeb-dev.md). Other agents depend on these being accurate.
