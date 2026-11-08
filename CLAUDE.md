# beebeeb core

This public Rust workspace is the cryptographic and protocol trust anchor for Beebeeb clients. The
workspace version is `0.3.0` and the license is AGPL-3.0-or-later.

## Commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build -p beebeeb-uniffi -p beebeeb-wasm
bash scripts/check-test-vectors.sh
bash scripts/check-no-legacy-writes.sh
bash scripts/check-doc-symbols.sh
bash scripts/check-core-pins-documented.sh
```

## Crates

- `beebeeb-core`: cryptography, file formats, key types, and pure rules.
- `beebeeb-types`: shared types.
- `beebeeb-api`: I/O-free typed API and account flows.
- `beebeeb-client`: native transport, per-app sessions, and product services.
- `beebeeb-store`: native local store.
- `beebeeb-transfer`: upload and download drivers, including range reads (`range_session` over core's
  `RangeOpener` and `RangePlanner`).
- `beebeeb-backup`: the desktop and CLI backup pass over a client's `BackupHost`, on core's pure
  `backup` rules.
- `beebeeb-wasm` and `beebeeb-uniffi`: web, Swift, and Kotlin bindings.
- `beebeeb-upload` and `beebeeb-sync`: legacy compatibility crates; do not build new products on them.

## Never break

The rules whose breakage costs data, a key, a credential or a user. The detail is in
[docs/agent-notes.md](docs/agent-notes.md), [docs/legacy-formats.md](docs/legacy-formats.md) and
[docs/client-rules.md](docs/client-rules.md).

Formats and keys:

- New files and new file versions are written as chunk format v2 with purpose subkeys (Guus's ruling of
  2026-11-07, which replaced the 2026-10-17 rule that a new file never is). The gate is on the clients:
  no client pins this release until web and iOS read v2 files and subkey-sealed thumbnails and the
  server's `BB_1908_SWITCH_GATE` is on. Readers keep only the compatibility paths in
  [docs/legacy-formats.md](docs/legacy-formats.md).
- A format, label, AAD, key derivation, info-string, point-encoding or binding change is a coordinated
  cross-client migration, never a refactor. A new derivation gets a new info string (`v2`); never change
  an existing one, never reinterpret existing bytes. Every label is listed in `label_table_tests.rs`.
- Writers record the format they wrote; never drop a recorded 2; an unknown recorded value is an error,
  never a fallback to detection. Never record `chunk_format: 2` on a file id with v1 history: its new
  versions are v2 under the kept unrecorded pin (`chunk_format_for_pin`) and MUST carry the version
  commitment. A replacement's counter is above both the served record's and the store's high-water mark.
- v2 frames never use the raw file key (key separation); `version_id` is frame 0's random 96-bit nonce.
- File-content readers take the format and version commitment from authenticated metadata
  (`decrypt_file_metadata[_with_key]`, never `decrypt_name_metadata`, never a server field), pass
  `chunk_format` on, and prefer `version_id()` over re-reading chunk 0's first 12 bytes. They finish
  authentication before publishing plaintext: call `finish()` and discard all plaintext on any `Err`.
  Every binding decryptor takes that decrypted record (`WasmChunkDecryptor`, `ChunkDecryptorHandle`) or
  its fields (`for_version*`); a missing record or half a commitment is refused. A v2 version opens only
  against its record's commitment (Guus's ruling of 2026-11-07): a `chunk_format: 2` record without one
  opens nothing, an unrecorded one opens v1 only, and the commitment-less constructors read v1 only.
  The one exception is `beebeeb_transfer::range_session`: it releases only frames that `RangeOpener`
  authenticated at the requested index, for one recorded version, and only its `RangeOutcome::Whole`
  result means whole content; after any failure its sink is not reused until it is verifiably empty.
  Its invariants I1 to I9 are in [docs/agent-notes.md](docs/agent-notes.md).
- Resume: `resume_policy` continues a stored session only for `(V1Legacy, V1Legacy)`. Otherwise the
  client MUST first `POST /api/v1/files/{id}/upload/abandon` and restart from chunk 0 in a new session;
  never PUT into the old session again, never fall back to it. The one exception is a v2 upload
  continuing itself: `beebeeb_transfer::background` resumes its own persisted session, same `version_id`
  and counter, from the next unstaged chunk (`resume_encryptor`) only when the restored state holds the
  whole commitment, the source identity matches and `staged_plaintext_matches`; anything else is
  `AbandonAndRestart`. A staged frame reaches the OS only after the state naming it was persisted
  (`to_bytes`), so a re-staged index never has a second frame on the server.
- Generic no-AAD `encrypt_chunk`/`decrypt_chunk` stays for key wraps, search shards and v1 content, never
  to seal a name, thumbnail or note under a per-file key. Notes are written with
  `encrypt_note_for(file_key, text, pin)` and read with `decrypt_note`, never with
  `encrypt_metadata`/`encryptFilename`/`encrypt_chunk`.
- A request row's `C` (`open_request_upload`) is decrypt-only: never seal a name, note or thumbnail under
  it. A rename seals via `seal_request_rename` / `sealRequestRename`; a request row has no note sealer.
- `UpperRepair` rows: core never writes under it and never migrates a row; a file is read-only if its
  name or any version reports it (SF-0002).
- Item ids: F ids are never derived (the key comes from an L8 owner envelope or an L7 child wrap);
  non-canonical id text is `InvalidInput`, never treated as an owner id. Canonical ids are UTF-8.
- Owner file-key wraps (L8) use the same textual encoding as L6 custody, never the binary UUID encoding
  of L7.
- Never fall back to a legacy opener after a purpose-bound one fails (the L6 custody opener, the legacy
  child, folder-key and invite openers). `kdf::open_legacy_child_key` refuses a 32-byte UTF-8 plaintext,
  so a name or label sealed under the same folder key is never served as a child key.
- Folder keys are random (`FileKeyHandle.generate`, OS CSPRNG), never derived from the master key.
  `folder_key_id` (`key_id`) is the one-way folder-key id: not secret, and never used as a key.
- `ClientMetaKey`: the derived key is never exported (a `FileKey` would also fit `encrypt_chunk`);
  `current_file`/`detail` are discarded from S1, never sealed.
- Contact safety numbers come only from `contact_keys::safety_number`, the one format web and the apps
  show (`safetyNumber`, `safety_number`); its vectors are `test-vectors/safety_number.json`. Emails go
  through `normalize_email` (Rust `str::trim`, then lower case), never a client's own: JavaScript's
  `trim` strips U+FEFF and keeps U+0085, so it would give a different number.

Secrets, input and bindings:

- Archives are hostile input (`archives`). Every entry name goes through `archives::names`, never a
  hand-joined path, so a `..` path is never written; the zip central directory is authoritative (a
  local header that disagrees with it is refused); a file is published only after its entry reads
  `Verified` (zip: CRC-32, and for AES the authentication code; a tar entry has no checksum of its
  own, and a tgz's gzip CRC-32 covers the whole stream, so a mismatch fails the run as `Damaged`
  after the files before it were published); a driver stages extracted bytes under a name the sync
  engine ignores (`<name>.bbtmp`, never the final name), renames or uploads only on `FileEnd`, and
  deletes on `FileSkipped`, cancel or failure (the native service stages
  `archive-<run>-<node>.bbtmp`, 0600); `PieceStep::Data` and `ExtractStep::FileData` print their
  length, never bytes; a ZipCrypto entry proves a password only when its CRC covers 4 bytes or more
  (an empty one passes any key its check byte lets through); a password is an `ArchivePassword`
  (zeroized, not `Clone`, never logged, never stored); the limits in `archives::limits` are core's, never raised by a
  client; hostile numbers use checked arithmetic. The old extension-based `archive` reader is gone;
  never bring back a second archive parser.
- `MasterKey` and `FileKey` are not `Clone`; intermediate key buffers are `Zeroizing`; crypto paths
  return `Result` and never panic. Secrets are wiped on drop and never appear in errors or debug output.
- Hostile sizes and counts use checked arithmetic and return errors; `MAX_CHUNK_SIZE` (256 MiB) rejects
  a hostile server-dictated chunk size.
- Passphrase NFC normalization never grows an unwiped secret buffer; core never seals a name its own
  opener refuses (`kdf::sanitize_actor_name`).
- `MIN_LENGTH_FLOOR = 12` is a floor applied inside `from_server` (the server may raise it, never lower
  it); there is no hard-coded fallback policy.
- Breach check: the SHA-1 suffix never leaves the device. The range request goes to Beebeeb's own
  endpoint, never the public HIBP API, and is made outside `beebeeb-core`.
- New product operations use opaque handles and purpose-specific APIs. The default UniFFI surface passes
  no raw key bytes. Behind the default-off `legacy-bindings` feature, raw key bytes still cross FFI in
  `open_request_upload` (the request content key `C`), `derive_master_key`, `derive_file_key`,
  `derive_request_wrap_key`, `recover_from_phrase`, `derive_share_key`, `derive_x25519_private`,
  `x25519_shared_secret`, `transfer_derive_key` and `MasterKeyHandle::export_for_keychain`: a migration
  target, not precedent. A handle is an ordered cursor driven from one sequence.
- Device link: the QR path takes only the scanned text (`DeviceLinkQr::parse`), never session,
  fingerprint or name bytes from a host or the server; on that path the typed code gives no protection
  against a substituted key. The QR (`beebeeb-link:v2:`) carries the canonical device name: the approver
  shows the scanned name, never the relay's, and `seal_for_new_device` refuses a relayed name that differs. The typed-code path is SPAKE2 with key confirmation bound to the session, a fresh
  salt and the canonical device name (`canonical_device_name`): the approver checks the new device's
  tag before it seals anything and denies the link when it fails; the new device checks the approver's
  tag before it opens. spake2 0.4 keeps unwiped copies of the code and its scalars (a recorded
  residual, in `device_link.rs`). Device-link labels change only as a new `v3`, never in place.
- Records that hold a secret redact it in `Debug` (`redacted_debug!` in `beebeeb-api`, `SecretString`
  / `SecretBytes` across UniFFI); a secret a person types or copies is also `Zeroizing`. A header value
  prints only when its name is in `DEBUG_VISIBLE_HEADERS`.
- The local store (`beebeeb-store`) caches decrypted names, MIME types, sizes and the tree in plaintext
  and holds no key or token; on Unix the database and its `-wal`/`-shm` are 0600. The Apple
  data-protection class is the app's to set.
- Native sign-in policy stays in `beebeeb-client`: password and any authenticator produce a locked
  session, then device approval or a passkey/recovery key plus email code supplies the account key,
  and key proof completes installation. Signup is web-only.
- Session storage has shared owner/key/API/generation state and one `session.token.{app_id}` per app.
  App sign-out removes one token; whole-device sign-out uses the service coordinator.

Transfers:

- `X-Beebeeb-Capabilities` goes only on the requests whose server behaviour it gates
  (`Endpoint::capabilities`), never globally. A session's transport never changes after init, so there
  is no mid-session API chunk.
- Direct-transfer failures carry a code and never a URL; the planner is a handle (one sequence's
  cursor). The presigned link is never a string past the binding: `WasmSignedUrl` and
  `DirectSignedUrl` print scheme and host only.
- Never retry into a sink that returned `DirectFailedAfterWrite`; after `UseApi` or any `Err` use a fresh
  sink. Direct-transfer clients write `<path>.bbtmp` and rename, never stdout straight to the driver.

Generated files, backups and this public repo:

- Generated bindings and vector JSON are generated, not hand-edited. The direct, range, backup,
  safety-number and name-clash vectors, and the case-folding table, each have a drift guard that fails
  on a hand edit: add rows in the generator, never in the JSON.
- Two names clash when their `name_tag::normalize_for_tag` forms are equal, never by lower case alone.
  A clash's second name comes from `name_clash` (`numbered_name` in a prompt, `drive_conflict_name` in
  the drive) and from the incoming name only, never from the existing item's.
- Backups: the root is the `backups_root` row, never a name or a path; a backup is written only by its
  device's own pass (the app and drive rules refuse every other create, write, rename and move under
  the root, and every change to a device's `.device.json`; the pass never goes through them); the pass
  never writes, moves, deletes, stages or hydrates a source file; a record at or under a key the walk
  did not look into (whatever its normal form or case) is never gone and never a move source; a pass
  marks a record only while it still names the remote id the pass read, and re-keys one only while it
  does or no record names that remote file (compare-and-set); only a complete remote listing marks
  anything removed elsewhere, and a removed file that changes comes back as a new file, never a
  version of the deleted one. Details are in [docs/agent-notes.md](docs/agent-notes.md).
- Backups, rebuild and stop: a rebuilt record needs `uploaded_at > modified + offset + margin` (a
  10-minute floor with no offset), never "uploaded after the device's mtime" alone; `backup_stop`'s
  `last_pass_at` is on the server's clock, never the device's; a stopped backup never fills the account
  up again by itself.
- Design files live in the workspace; never copy them into this public repo (a snapshot once published
  a false external-audit claim, and the claims guard fails on those strings).

All consumer boundaries, including the web exception and version-pin rule, are in
[docs/client-rules.md](docs/client-rules.md). Detailed format and key notes are in
[docs/agent-notes.md](docs/agent-notes.md).
