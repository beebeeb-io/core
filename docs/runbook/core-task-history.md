# beebeeb-io/core — task history archive

Created 2026-10-24 when `repos/core/CLAUDE.md` was distilled to evergreen rules only
(≤150 lines). This file is the pre-distillation `CLAUDE.md` preserved verbatim so that
nothing was deleted: every rule, ruling, incident narrative, proof reference and command
history survives here. `CLAUDE.md` now holds the evergreen distillation and points here
for the details of moved content.

---

# beebeeb-io/core

Cryptographic core, shared types, and sync engine. This is the trust anchor — every client depends on this.

## Crates

- `beebeeb-core` — AES-256-GCM encryption, Argon2id KDF (256MiB/4iter/2par), BIP39 recovery phrases, HKDF per-file key derivation, onboarding (password policy evaluator, breach-check helper, signup ceremony state machine)
- `beebeeb-types` — CipherSuite, EncryptedBlob, KdfParams, ChunkMeta (shared across all repos)
- `beebeeb-sync` — Desktop sync engine: file watcher (notify), conflict resolution (KeepBoth default), selective sync

## Build & test

```sh
cargo test -p beebeeb-core   # 495 tests across 9 binaries (unit 422, chunk_stream_parity 2, cli_auth_vectors 4 + 1 ignored, cross_client_vectors 21, cross_platform_vectors 22, integration 13, transfer_vectors 5, zip_tests 6) + 1 doctest — measured 2026-10-17 on fix/1908-chunk-aead-binding review round 5 (base cbd941b, where unit was 349; round 3 unit 402, round 4 unit 412); the truth line is per binary: `test result: ok. N passed`
cargo test --workspace       # full workspace (core + sync + types + upload + uniffi + wasm)
cargo clippy --workspace -- -D warnings
cargo fmt -- --check
```

## Key types

- `MasterKey` — 32 bytes, NOT Clone, zeroized on drop. Created from password (Argon2id) or recovery phrase.
- `FileKey` — 32 bytes, per-file via HKDF. `derive_file_key(master_key, file_id)`.
- `EncryptedBlob` — cipher_suite + nonce (Vec<u8>) + ciphertext (Vec<u8>).
- `encrypt_chunk(key: &FileKey, plaintext)` / `decrypt_chunk(key: &FileKey, blob)` — generic AES-256-GCM, NO associated data (key wrap, search shards). **Not for file content** — file chunks go through `chunk_stream` (chunk format v2, task 1908) — **and not for names, thumbnails or file notes** — those go through `encrypt_name*` / `decrypt_file_metadata`, `encrypt_thumbnail[_for]` / `decrypt_thumbnail` (purpose subkeys, task 1908 round 3) and `encrypt_note[_for]` / `decrypt_note` (round 5).

## Shared folder key id (`folder_key.rs`, task 2133)

`folder_key::folder_key_id(folder_key: &[u8; 32]) -> [u8; 32]` =
HKDF-SHA256(ikm = the folder key, salt = none, info = `b"beebeeb/folder-key-id/v1"`).
It is a one-way id of a shared folder's key, meant for a server to compare
folder keys without learning them; a client finds which of its candidate keys an
id names by recomputing it. With no salt, the extract step is HMAC-SHA256 under
an all-zero salt over the key. The id commits to the key it was computed from but
cannot prove that wraps sent with it were made under that key. It is not secret
and must never be used as a key. A new derivation gets a new info string (`v2`),
never a change to this one.

- Exports: WASM `folder_key_id(folder_key: Uint8Array) -> Uint8Array`; UniFFI
  `folder_key_id(folder_key: Vec<u8>) -> Vec<u8>`. Both refuse a key that is not
  32 bytes and wipe the copy the function owns (the UniFFI lift buffer and
  wasm-bindgen's copy are freed without a wipe, as everywhere in these crates).
- Vector: `folder_key_id` in `test-vectors/vectors.json` (version 7), under the
  `test_vectors_v2` drift guard; the expected id was computed outside the crate
  (RFC 5869 in Python, checked against the RFC's test case 3).

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
- **Wire format:** `nonce(12) || ciphertext || tag(16)`, fresh random nonce per
  chunk; same layout and sizes in both chunk formats (see "Chunk format v2" below).
  New files are still written as **v1** during the read-only rollout phase
  (`WRITE_FORMAT`, task 1908); every reader reads v1 and v2.
- `file_encrypt::encrypt_file_to_chunks` now **DELEGATES** to `ChunkEncryptor`
  (one encrypt loop, no drift); `tests/chunk_stream_parity.rs` enforces an
  identical chunk plan + that the output is a `WRITE_FORMAT` stream (decrypts via
  `ChunkDecryptor`; opens with the legacy no-AAD `decrypt_chunk_raw` iff v1).
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
  the first stateful `#[wasm_bindgen]` struct in the crate. `WasmChunkDecryptor`
  (task 1908) is the matching push decryptor; web file content must use it (or
  `decrypt_chunk_frame` for random access), not the generic `decrypt_chunk`.

### Chunk format v2 — position binding (task 1908)

**Problem (v1):** every frame was AES-256-GCM under the one per-file key with NO
associated data. Cross-file swaps failed (different keys), but WITHIN a file a
malicious server could reorder, duplicate, drop, or truncate frames undetected,
and splice frames of two versions of one file (a replace keeps the file id, so
all versions share the key).

**v2 = same frame layout, own subkey, AAD = position (STREAM, Hoang–Reyhanitabar–Rogaway–Vizár; as in age / Tink):**

```text
key = HKDF-SHA256(ikm = file_key, salt = none, info = "beebeeb/chunk/v2/key")
AAD = "beebeeb/chunk/v2"         16 bytes: domain tag + version
   || u32_be(len(file_id))       length prefix (injective encoding)
   || file_id                    exact bytes fed to derive_file_key (string UUID)
   || version_id                 12 bytes: the nonce of THIS upload's frame 0
   || u32_be(chunk_index)        0-based
   || u8(is_last)                1 on the final chunk only
```

- `chunk_stream::chunk_aad_v2` builds the AAD; `CHUNK_AAD_DOMAIN_V2`,
  `CHUNK_KEY_INFO_V2`, `VERSION_ID_LEN`, `ChunkFormat` (`V1Legacy` = 1, `V2` = 2),
  `ExpectedChunkFormat` (`Unrecorded` = 0, `V2` = 2) and `WRITE_FORMAT` are
  public. KATs: `chunk_aad_v2_known_answer` (layout),
  `chunk_subkey_v2_known_answer` (subkey, computed independently in Python).
- **Subkey (review round 2):** v2 frames never use the raw file key, which also
  seals the encrypted name/MIME and thumbnails with no AAD. Key separation, so no
  blob of another type can ever open as a v2 frame (test
  `v2_frames_are_sealed_under_the_chunk_subkey_not_the_file_key`).
- **Version id (review round 2, P1-2; Guus's 1778 ruling "file VERSION id" in
  the AAD):** the random 96-bit nonce of the upload's frame 0. Client-generated,
  unique per upload, carried in frame 0 and authenticated by every frame (frame
  0's AAD includes its own nonce). A frame from another version of the same file
  id fails, so middle splices and truncation with another version's last frame
  are rejected. **Deliberately not stored in the file metadata** (deviation from
  the review's suggestion, recorded in task 1908): the server keeps ONE
  `name_encrypted` per file (`file_versions` has no metadata column), so a
  metadata-held id could not open older versions, and a pre-1908 client's rename
  would drop it and make the file unreadable. What the in-band id does NOT
  prevent: serving a whole older version (rollback) — a metadata-held id would
  not prevent that either, since the server can roll the metadata back too.
- **No total count in the AAD (decided):** the last flag gives the same
  truncation/extension guarantee without the decryptor knowing the count up
  front; a server lie about the count makes the frame it calls last (or not
  last) fail the tag.
- **file_id is in the AAD although the key is already HKDF(master, file_id):**
  defence in depth for any two files that ever share a key (unwrapped content
  keys, reused/mis-derived keys).
- **Where the decryptor learns the format — mandatory pin (review round 2,
  P1-1):** every reader REQUIRES an `ExpectedChunkFormat` from the file's
  encrypted metadata, read with the FILE reader
  `encrypt::decrypt_file_metadata[_with_key]` (round 3 — it refuses plaintext
  names; `decrypt_name_metadata` is for folders/display):
  - `V2` — the metadata records `"chunk_format": 2`: only v2 frames open, no
    detection. Closes the downgrade where the server serves the file's own name
    blob (or thumbnail) — a no-AAD blob under the same key — as a one-frame
    "v1 file" (tests `p1_1_*`).
  - `Unrecorded` — metadata without the field (every file written before the
    v2 switch, or metadata rewritten by a pre-1908 client): frame 0 decides (v2
    tried first, then v1), then the format is LOCKED. Detection is unambiguous
    between v1 and v2 FRAMES (a v1 frame spliced at position >= 1 of a v2 file
    fails the lock) but NOT at position 0 against other no-AAD blobs under the
    same key: for such files a server can still pass the name blob off as the
    whole file. This is the residual of keeping v1 readable; it is pinned by
    `residual_unrecorded_metadata_still_detects_documented`.
  - Writers record it with `encrypt::encrypt_name_with_chunk_format`
    (`encrypt_name` = `Unrecorded`, byte-identical to before). Semantics:
    `chunk_format: 2` asserts EVERY upload of this file id is v2 (readers of old
    versions pin with the same per-file metadata). New file: `recorded_for(enc.format())`.
    Rename / replace: carry forward the decrypted value — never upgrade a file id
    with v1 history, never drop a recorded 2 (dropping silently re-enables
    detection for that file). An unknown or non-numeric recorded value is an
    error, never a fallback to detection.
  - Plaintext names (round 3, P1-B): `decrypt_name_metadata` still reads a
    plaintext (non-JSON) `name_encrypted` as a legacy name (`Unrecorded`) —
    folders need that. `decrypt_file_metadata` REFUSES it, so a server can no
    longer re-enable detection for a v2 file by replacing its metadata with a
    plaintext name (tests `p1b_file_reader_refuses_*`,
    `p1b_plaintext_name_substitution_on_a_v2_file_is_refused`).
- **Decrypt rules (`StreamOpener`, crate-private, used by every file-content
  decrypt path):** frame i opens only at index i and (v2) under frame 0's
  version id; nothing may follow the frame sealed as last; `finish()` (push) /
  EOF (pull) fails unless a v2 stream saw its last frame; zero frames is always
  an error. Trial opens are safe and cheap: aes-gcm 0.10.3 checks the tag before
  applying the keystream (a failed trial never produces plaintext).
- **Random access** (seeking readers): `chunk_stream::open_chunk(file_key,
  file_id, version_id, index, is_last, format, frame)` — `format` from the
  metadata pin (or a decryptor that opened chunk 0), `version_id` from
  `ChunkDecryptor::version_id()` after chunk 0 (or chunk 0's first 12 bytes:
  if those are forged, only the frames of the one version they belong to open).
- **Public API changes:** `ChunkDecryptor::{from_reader, for_push,
  for_push_with_file_key}`, `encrypt::{decrypt_chunks_to_file,
  decrypt_contiguous_to_file}`, `file_encrypt::decrypt_chunks_to_file`,
  `zip::ZipEntry.chunk_format`, `beebeeb_upload::{decrypt_downloaded_bytes,
  download_and_decrypt_file, DownloadClient::download_and_decrypt}` take the
  expected format (and the file id); `open_chunk` takes the version id. New:
  `ChunkDecryptor::{version_id, format, chunks_decrypted, finish}`,
  `ChunkEncryptor::format`, `encrypt::{NameMetadata, decrypt_name_metadata,
  decrypt_name_metadata_with_key, encrypt_name_with_chunk_format}`. UniFFI:
  `expected_chunk_format: u8` on `decrypt_chunks_to_file`,
  `decrypt_contiguous_to_file`, `download_and_decrypt_file`,
  `MasterKeyHandle.decrypt_file`, `ChunkDecryptorHandle.{from_file, for_push,
  for_push_with_file_key}`; new `ChunkDecryptorHandle.{for_push_with_file_key_handle
  (preferred: the raw key never reaches Swift), version_id, chunk_format, finish}`,
  `MasterKeyHandle.{encrypt_name_with_chunk_format, decrypt_name_metadata}`,
  `FileKeyHandle.{decrypt_name_metadata, decrypt_chunk_frame(file_id, version_id, ...)}`,
  `ChunkEncryptorHandle.chunk_format`. WASM: `WasmChunkDecryptor(masterKey,
  fileId, expectedChunkFormat)` / `fromFileKey(fileKey, fileId,
  expectedChunkFormat)` + `pushFrame`, `format`, `versionId`, `chunksDecrypted`,
  `finish`; `decrypt_chunk_frame(fileKey, fileId, versionId, ...)`,
  `encrypt_name_with_chunk_format`, `decrypt_name_metadata[_with_key]`,
  `WasmChunkEncryptor.format`. Round 4: `chunk_stream::chunk_format_for_pin`,
  `ChunkEncryptor::with_recorded_pin`, `encrypt::{metadata_seal_for,
  encrypt_thumbnail_for}`; UniFFI `ChunkEncryptorHandle.apply_recorded_pin`,
  `FileKeyHandle.encrypt_thumbnail_for`; WASM `WasmChunkEncryptor.withRecordedPin`,
  `encrypt_thumbnail_for`. Round 5: `encrypt::{NOTE_KEY_INFO, encrypt_note,
  encrypt_note_for, decrypt_note}`; UniFFI `FileKeyHandle.{encrypt_note,
  encrypt_note_for, decrypt_note}`; WASM `encrypt_note`, `encrypt_note_for`,
  `decrypt_note`.
- **Not v2 (unchanged, generic no-AAD):** `encrypt_chunk` / `decrypt_chunk` /
  `encrypt_chunk_raw` / `decrypt_chunk_raw` / `encrypt_chunk_json` and WASM
  `decrypt_chunks` — key wrap, search shards, v1 content (and legacy names and
  thumbnails). They must not be used for file content, and never to SEAL a name,
  thumbnail or file note under a per-file key (a no-AAD blob under that key is
  indistinguishable from a v1 content frame; `encrypt_metadata` under that key
  is indistinguishable from a legacy name envelope).
- **Metadata sealing — names and thumbnails (review round 3, P1-B):**
  ```text
  name key  = HKDF-SHA256(ikm = file_key, salt = none, info = "beebeeb/name/v1")
  thumb key = HKDF-SHA256(ikm = file_key, salt = none, info = "beebeeb/thumb/v1")
  note key  = HKDF-SHA256(ikm = file_key, salt = none, info = "beebeeb/note/v1")   (round 5)
  ```
  Before this, the name/MIME envelope and thumbnails were sealed under the RAW
  file key with no AAD, exactly like a v1 content frame, so a server could serve
  them as a one-frame "file" wherever the reader detects the format. A
  subkey-sealed name or thumbnail never opens as content (v1: raw key; v2: chunk
  subkey + AAD) or as the other (tests `p1b_subkey_sealed_*`,
  `p1b_name_and_thumbnail_subkeys_are_distinct_*`; KATs
  `name_subkey_known_answer`, `thumbnail_subkey_known_answer`). `kdf::derive_file_subkey`
  is the one HKDF helper for all three purpose subkeys.
  - Readers: every name reader (`decrypt_name`, `decrypt_name_with_mime`,
    `decrypt_name_with_key`, `decrypt_names`, `decrypt_name_metadata*`,
    `decrypt_file_metadata*`) and `encrypt::decrypt_thumbnail` try the subkey
    first, then the legacy raw key, so every blob already stored keeps opening.
    `decrypt_metadata` / `decrypt_chunk` on a parsed envelope do NOT try the
    subkey — clients must not open names or thumbnails that way.
  - Writers: a name that records `chunk_format: 2`, and a thumbnail written with
    `encrypt::encrypt_thumbnail_for(file_key, plaintext, V2)` (round 4, P2-4),
    are ALWAYS subkey-sealed (only a reader on this core can open v2 content
    anyway). Everything else follows `encrypt::METADATA_SEAL_WRITE` =
    `metadata_seal_for(WRITE_FORMAT)`, which is `Legacy` during the read-only
    phase. ONE rule for content, names and thumbnails (round 4, P2-1):
    `chunk_stream::chunk_format_for_pin(pin)` (V2 → V2, Unrecorded →
    `WRITE_FORMAT`) then `encrypt::metadata_seal_for(format)` (V1Legacy →
    Legacy, V2 → Subkey); both arms of both functions are pinned by tests
    (`i1_unrecorded_pin_writes_the_write_format`, `p2_1_metadata_seal_for_both_arms`). **Deviation from the lead's round-3
    ruling ("seal NEW name metadata and thumbnails under their own subkeys from
    now on"), flagged in task 1908:** sealing new v1-file names and thumbnails
    under the subkey today would make them unreadable on every client not yet on
    this core (web `thumbnail.ts`, mobile, older builds), and there is no v2 file
    yet for it to protect. Both switches flip in ONE gated release.
  - Thumbnails are sealed ONLY via `encrypt::encrypt_thumbnail` (new file;
    UniFFI `FileKeyHandle.encrypt_thumbnail`, WASM `encrypt_thumbnail`) or
    `encrypt::encrypt_thumbnail_for(file_key, plaintext, pin)` (existing file,
    pin from `decrypt_file_metadata`; UniFFI
    `FileKeyHandle.encrypt_thumbnail_for(plaintext, recorded_pin)`, WASM
    `encrypt_thumbnail_for(fileKey, plaintext, recordedPin)`), wire format
    unchanged (`nonce || ct || tag`).
  - **File notes (review round 5; spec `docs/specs/2026-10-17-1912-legacy-file-reseal.md`
    §6, lead ruling 2026-10-17):** web sealed `files.note_encrypted` with
    `encrypt_metadata(rawFileKey, text)` (`file-details-panel.tsx` ~247) — an
    `EncryptedBlob` JSON in exactly the shape of a legacy name. Served as a v2
    file's `name_encrypted`, the name reader's legacy fallback opened it, the
    non-JSON note text read as a name with NO pin (`Unrecorded`), detection was
    back on, and the same note bytes then opened as a one-frame v1 "file": a
    raw-key note undid the v2 pin. Notes now have their own subkey and the same
    seal rule as names and thumbnails: `encrypt::encrypt_note_for(file_key,
    text, pin)` (existing file, pin from `decrypt_file_metadata`; a v2 pin is
    ALWAYS subkey-sealed, `Unrecorded` follows `METADATA_SEAL_WRITE`) and
    `encrypt::encrypt_note(file_key, text)` (no pin yet = `METADATA_SEAL_WRITE`);
    both return the canonical `EncryptedBlob` JSON web already stores.
    `encrypt::decrypt_note` tries the note subkey, then the legacy raw key
    (both envelope shapes) and refuses plaintext. A note sealed for a v2 file
    never opens through any name reader, as content (either pin), as a
    thumbnail, and no name/thumbnail/content frame opens as a note (tests
    `raw_key_note_served_as_name_downgrades_v2_file`, `review_round5_tests`;
    KAT `note_subkey_known_answer`, Python-computed).
  - Residual (decision task 1912): a file written before the switch has a
    legacy name and/or thumbnail under the same raw key as its v1 content and no
    pin, so a server can still serve one of them as that file's content. Old
    blobs cannot be retired by rewriting them — the server can keep and replay
    the old copies.
- **Resumed uploads (review round 3, P1-A):** the server keeps the frames an
  upload session already holds and skips re-PUTs of those indices. A v2 upload's
  frames all bind one version id (its frame 0 nonce); a resumed upload builds a
  NEW encryptor with a NEW version id, so continuing the old session stores two
  version ids side by side — a file that completes and can never be read
  (`p1a_continuing_the_old_session_with_a_new_v2_encryptor_is_unreadable_documented`).
  Re-creating the old id is not an option: it is a nonce. Rule:
  `chunk_stream::resume_policy(stored, writing)` /
  `ChunkEncryptor::resume_policy(stored)` → `SessionResume::ContinueSession` only
  for `(Some(V1Legacy), V1Legacy)`; everything else, INCLUDING a resume record
  that does not say which format it holds (`None`), is
  `RestartWithFreshSession`: never PUT to the old session again, upload from
  chunk 0 into a new session. Clients persist `ChunkEncryptor::format()` next to
  the session id when they open it.
  **The restart path, precisely (round 4, P2-3; server `routes/uploads.rs`
  init + `routes/files.rs` abandon, server 8eca915c):** the server refuses a new
  init for a file whose session still holds a live lease (409 "upload is
  already in progress for this file"). So a client told
  `RestartWithFreshSession` MUST first `POST /api/v1/files/{id}/upload/abandon`
  (a replace reverts to the previous version; a never-completed first upload
  is deleted), or wait until the lease expires (default 3600 s,
  `UPLOAD_LEASE_SECS`; an init after expiry takes the session over inline),
  and only then init again with the same file id and upload from chunk 0
  with the new encryptor. On a 409 from that init it retries the abandon /
  waits; it NEVER falls back to PUTting into the old session — that is exactly
  the two-version-id file that completes and never opens. UniFFI `ChunkEncryptorHandle.resume_policy(stored_format)`
  → `SessionResumeAction`; WASM `WasmChunkEncryptor.resumePolicy(storedFormat)`
  → `"continue"` / `"restart"`. Pinned by `p1a_probe_b_*` and `p1a_resume_policy_matrix`.
- **Client adoption checklist (every client, before it ships on this core):**
  1. Read a file's content pin with `decrypt_file_metadata[_with_key]` (never
     `decrypt_name_metadata`, never a server field) and pass its
     `chunk_format` to every content reader. Folders keep `decrypt_name_metadata`.
  2. Take the chunk format from the pin (or from a decryptor that opened chunk
     0), never from a server-supplied value. For seeking readers, prefer
     `ChunkDecryptor::version_id()` (UniFFI/WASM `versionId`) over re-reading
     chunk 0's first 12 bytes.
  3. Call `finish()` on every decryptor after the last frame, and DISCARD all
     plaintext already produced (delete the partial file, drop the buffer) when
     any `push_frame` / `next_chunk` / `finish` returns `Err` — a truncated or
     spliced file is detected only at that point.
  4. **Every replace / new version uses the file's recorded pin (round 4,
     I-1); a NEW file never does (lead ruling 2026-10-17).**
     `with_recorded_pin` / `apply_recorded_pin` / `withRecordedPin` take `V2`
     ONLY with the pin read from an EXISTING file's authenticated metadata. A
     brand-new file id uses the plain constructor (= `WRITE_FORMAT`) and
     records what it wrote (item 5); passing `V2` for a new file would create
     a v2 file before the switch that clients not yet on this core cannot
     read. Core cannot tell the two apart, so each client ships a test that
     its new-file path never passes `V2` (runnable example: the doctest on
     `ChunkEncryptor::with_recorded_pin`). Read the pin with `decrypt_file_metadata` and build the writer
     with `ChunkEncryptor::with_recorded_pin(pin)` (UniFFI
     `ChunkEncryptorHandle.apply_recorded_pin(recorded_pin)` right after the
     constructor; WASM `enc = enc.withRecordedPin(recordedPin)`), its thumbnail
     with `encrypt_thumbnail_for(.., pin)`, its note with
     `encrypt_note_for(.., pin)`, and, if the name is rewritten,
     `encrypt_name_with_chunk_format(.., pin)`. The server keeps a file's
     `name_encrypted` on replace (server `routes/uploads.rs` ~907-923), so a
     v2-pinned file replaced with the default (v1, read-only phase) writer
     would complete and never open (`i1_probe_*`); a v2 pin therefore forces v2
     frames even before the switch. If the pin cannot be read, do not upload.
  5. Record the format at upload of a NEW file:
     `encrypt_name_with_chunk_format(..., recorded_for(enc.format()))`; on
     rename/replace carry forward the value `decrypt_file_metadata` returned.
  6. Seal and open thumbnails only with `encrypt_thumbnail` (new file) /
     `encrypt_thumbnail_for` (existing file) / `decrypt_thumbnail`; open names
     only through the `decrypt_name*` / `decrypt_*_metadata` readers.
  6a. **File notes go through core (round 5).** Write with
     `encrypt_note_for(file_key, text, pin)` (pin from `decrypt_file_metadata`
     of that file; `encrypt_note` only where the file has no pin yet), read
     with `decrypt_note`. Never `encrypt_metadata` / `encryptFilename` /
     `decryptFilename` / `encrypt_chunk` for a note. **Web follow-up (not in
     core):** `repos/web` `src/components/file-details-panel.tsx` ~218 (read:
     `parseEncryptedBlob` + `decryptFilename`) and ~247 (write:
     `encryptFilename` + `serializeEncryptedBlob`) must call WASM
     `decrypt_note` / `encrypt_note_for(fileKey, text, pin)`. **Mobile / CLI /
     desktop:** no note code today (grep of `note_encrypted` on 2026-10-17); any
     future note UI uses UniFFI `FileKeyHandle.{encrypt_note_for, decrypt_note}`.
  7. Resuming an upload session: ask `resume_policy(stored_format)` and obey it
     (restart path above: abandon or lease expiry first, never the old session
     on a 409); persist the encryptor's format with the session id. CLI
     follow-up: `repos/cli` `src/resume.rs` + `src/upload.rs` must record the
     format and start a fresh session when told `RestartWithFreshSession`.
- **Rollout (read-only phase now):** `WRITE_FORMAT = ChunkFormat::V1Legacy`.
  A client on this core reads v2 but writes v1, because a v2 file is unreadable
  by every client whose read path is not yet on this core (web `decrypt_chunk` /
  `decrypt_chunks` loops, mobile video streamer / FileProvider, older builds).
  The switch to v2 writes is a separate, gated core release once every client's
  read path (with the metadata pin) is live — task 1908. Tests that need v2
  frames use `ChunkEncryptor::with_format`, compiled only under `cfg(test)` or
  the `test-support` feature, which the binding crates enable in
  `[dev-dependencies]` only. The ONE shipped way to write v2 before the switch
  is `with_recorded_pin(V2)`, i.e. a new version of a file whose authenticated
  metadata already records v2 (round 4, I-1).
  **Switch gate (server follow-up, not in core):** before `WRITE_FORMAT` flips,
  the server must reject replace inits (`base_version_number` set) from client
  versions older than 1908 round 4 — such a client writes v1 frames under the
  v2 pin the server keeps, i.e. an unreadable new version (task 1908 notes).
  The same gate must reject `PATCH name_encrypted` (a pre-1908 rename drops the
  pin) and `PATCH note_encrypted` (a pre-round-5 client seals the note under
  the raw key) from older clients (round 5; spec 1912 §3.7 item 5). The note
  writers follow the same switch: notes of `Unrecorded` files stay raw-key
  sealed until `WRITE_FORMAT` flips.

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
  its password plus the recorded answer (`new(password)`, `prefix()`, `record(requested_prefix, response)`
  (task 1767: refuses with `BreachError::PrefixMismatch`, code `breach_prefix_mismatch`, and records
  nothing when `requested_prefix` is not this password's prefix, case-insensitively, because a
  body for another prefix would evaluate as clean; pass the prefix the request URL or cache entry
  actually used), `verdict(fail_open)`, `matches_password(pw)`). **The HTTP call stays in each client and goes
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
  `WasmBreachCheck` (`new(password)`, `prefix`, `evaluate(requestedPrefix, body|null, failOpen)` which
  records the answer and returns the display verdict, throwing `breach_prefix_mismatch` on a wrong
  prefix). Password parameters (`evaluate_password`, `WasmBreachCheck.new`, `setPassword`,
  `setPasswordUnchecked`) take an owned `String` held in `Zeroizing` (task 1767), and `confirmPhrase`
  answers are held as `Zeroizing<String>`; the JS-side string itself cannot be wiped; `WasmSignupCeremony(minLength, emailVerificationRequired,
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
  Option<BreachCheckHandle>)`, `BreachCheckHandle.evaluate(requested_prefix, body, fail_open)` (throws
  `OnboardingError.BreachPrefixMismatch`), `confirm_phrase` answers held as `Zeroizing`, `abandon()`, `email_changed()`; `account_created()` returns a
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
  one `test result: ok. N passed; 0 failed` per crate/suite (the CLAUDE.md numbers above — 475 across
  9 binaries for `beebeeb-core`, measured 2026-10-17 (405 before task 1908, 358 before task 1744) — are the baseline to compare against). Assert the Ns; a suite that did not run is
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
