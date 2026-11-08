# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.7] - 2026-11-08

Windows: a create by name never touches a different file that the OS resolves the name to (8.3 alias), task 2404.
Additive: no public item is renamed, retyped or removed.

### Fixed

- **Windows: a create, truncate, replace or delete by name only ever touches the entry with that exact long name.**
  Windows also resolves a name through the 8.3 short names of a directory, so a name could reach a different existing
  file. Such a name is now a name conflict, decided from the existing entry's own long name as the file system reports
  it (case-insensitive, as NTFS compares), never from the shape of the name.
  - `path_safety::safe_child`, `safe_rel_join` (every existing segment) and `default_output_path` refuse it (their
    `String` error names the conflict).
  - `encrypt::decrypt_chunks_to_file`, `encrypt::decrypt_contiguous_to_file`, `file_encrypt::decrypt_chunks_to_file`
    and `file_encrypt::encrypt_file_to_chunks` refuse such an output before creating anything
    (`CoreError::InvalidInput` naming the conflict), and so do beebeeb-upload's downloads (`UploadError::InvalidInput`).
    Their temp file is created exclusively: `{output}.tmp`, or `{output}.{16 hex}.tmp` when that name is taken (a temp
    left by a crash, or a file of the user's own), so an existing entry is never opened, truncated or deleted. On
    Windows, an output that did not exist is published without replacing (a hard link, or on a volume without hard
    links an exclusive create and a rename over it): an entry created there meanwhile fails the write.
  - An 8.3-shaped name that the file's handle reports as its own long name is confirmed against the directory listing
    (some network redirectors and third-party drivers report the name as opened).
  - beebeeb-sync's remote delete never deletes the file such a name reaches.
  - Other hosts: no extra file-system calls, and no change but two: beebeeb-sync's remote delete drops a state row that
    is not a relative path of plain names (`..`, absolute) instead of deleting `vault/<path>`, and the item below.
- **`file_encrypt::decrypt_chunks_to_file` writes `{output_path}.tmp`, as its docs say** (it wrote
  `output_path.with_extension("tmp")`, which is the output itself for `notes.tmp`: a failed decrypt truncated and then
  deleted that file, and `a.pdf` and `a.doc` in one folder shared one temp file).

### Added

- `path_safety::short_name_alias(base, rel) -> io::Result<Option<ShortNameAlias>>` (native targets) and
  `path_safety::ShortNameAlias { requested, existing }` (`#[non_exhaustive]`): the typed answer for a caller that has a
  conflict path ("(2)", a conflict copy) and takes it instead of refusing.
- `path_safety::TempSibling` (native targets): `create(output) -> io::Result<(TempSibling, File)>`, then
  `publish(self) -> io::Result<()>`; dropped unpublished, it removes its temp. The write-then-publish step every core
  writer and beebeeb-upload use, for a client that writes a file by name itself.

### Known limits

- The case-insensitive comparison uses Rust's Unicode tables; NTFS uses the volume's `$UpCase` table, written at format
  time (it maps `ı` and `ſ` to themselves; older tables lack newer case pairs). Erring needs a long name equal to the
  requested short name but for such letters.

## [0.2.6] - 2026-11-08

Fixes to the folder-zip writer `zip::stream_folder_zip` (LD-0146, core #89, #90 and #91): an entry of 4 GiB or more is
written as ZIP64 instead of failing the archive; a cancelled or failed archive is no longer a valid-looking, shorter zip;
a duplicate path is stored as `name (2).ext` and never takes the path of a folder; and progress ends at exactly 100%.
The public API is the same: no signature or type is renamed, retyped or removed. No caller on main uses
`stream_folder_zip` yet (the cli writes its own archives), so no client has to move for this tag.

### Fixed

- **`zip::stream_folder_zip` (LD-0146); no signature or type changes.**
  - An entry of 4 GiB or more no longer fails the archive partway ("Large file option has not been set"): an entry whose
    declared `size_bytes` is 3 GiB or more is written as ZIP64. Smaller entries keep the layout they had.
  - A cancelled or failed archive is no longer a valid-looking, shorter zip. The dropped `ZipWriter` used to finish
    the current entry with a short CRC and write a central directory; the writer is now sealed on every exit but the
    finished archive (an `Err`, a cancel, a panic in a callback) and by the first failure of the sink itself (a write,
    a seek or a flush; an interrupted call is retried), so a sink that fails once in the central directory and then
    works again cannot take a second, complete central directory from the zip crate's retry in `Drop`. No central
    directory follows the failure and no reader opens the output as complete; the one exception is a sink that fails on
    the last seek after the footer is written. The caller still deletes the file on `Err`. The zip crate reports the refused footer on
    stderr (`ZipWriter::drop: failed to finalize archive: ...`, with no trailing newline); core cannot silence it.
  - Two entries with the same path no longer abort the archive: the later one is stored as `name (2).ext`,
    `name (3).ext`, ... (the cli's rule), compared case- and normalisation-insensitively and without empty components (`a//b`), as macOS and Windows
    extract.
    An entry's own name is never taken by a rename, and neither is a path that is another entry's folder (`report`,
    `report`, `report (2)/notes.txt` gives `report`, `report (3)`, `report (2)/notes.txt`); a file named like another
    entry's folder is renamed too.
  - `ZipProgress::bytes_done` counts plaintext, and each entry's declared `size_bytes` (plaintext for web uploads,
    encrypted for cli uploads) is replaced in `bytes_total` by the plaintext read once its last chunk is in, so the
    last event is exactly 100% (it counted ciphertext and ended above it for web uploads). No event reports more than
    100%, even for an understated or zero `size_bytes`, and the fraction done does not fall back when such an entry
    ends.
  - The sum of the entries' `size_bytes` (also in `estimate_zip_size`) saturates instead of overflowing.

## [0.2.5] - 2026-11-08

Additive on v0.2.4: a backup pass reads the removal notices with an overlap margin and remembers the notice ids it
acted on (LD-0121, spec `2026-11-06-backup-from-source-design.md` Amendment 12d, server #415 review finding 1; Guus
2026-11-08 03:16, "Go w recommended"). No v0.2.4 API is renamed, retyped or removed.

### Fixed

- **A backup pass could miss a removal notice because of transaction timing.** A notice's `created_at` is the start
  of the server transaction that writes it, not its commit. A pass that read the notices while that transaction was
  still open did not see it, then recorded a `last_pass_at_ms` later than the notice, and the strict
  `created_at_ms > last_pass_at_ms` of `backup_stop` / `backup_pass_gate` never counted it afterwards. In the worst
  case (row 10, the billing grace clock) the backup uploaded again the files the server had just deleted. The v0.2.3
  functions (unchanged in v0.2.4) keep that behaviour, now documented as superseded; clients move to the v2 functions below.

### Added

- **`beebeeb_core::backup`**: `NOTICE_OVERLAP_MS` (10 minutes); `notices_since(last_pass_at_ms)`, the inclusive
  `since` to send to `GET /api/v1/notifications` (`last_pass_at_ms - NOTICE_OVERLAP_MS`, never below 0);
  `ListedNotice { id, notice, created_at_ms }`; `backup_stop_v2(notices, last_pass_at_ms, acknowledged, listing)`
  returning `StopOutcome { stopped, acknowledged }`; and `backup_pass_gate_v2(notices, last_pass_at_ms, acknowledged,
  listing)` with `BackupPassGateV2::{Run { stopped, acknowledged }, CheckFailed}`. A notice counts when
  `created_at_ms > last_pass_at_ms - NOTICE_OVERLAP_MS` and its id is not acknowledged. `acknowledged` in the
  answer replaces the stored set: every id in the window, sorted, once each. It is stored in the same write as the
  stops and the new `last_pass_at_ms`, and kept when the person chooses "Back up again". A notice with no id, or an
  empty one, is never acknowledged.
- **Bindings**: uniffi `backup_notice_overlap_ms`, `backup_notices_since`, `backup_stop_v2` (`BackupNoticeRowV2`,
  `BackupStopOutcome`) and `backup_pass_gate_v2` (`BackupPassGateV2`), 4 in all; wasm `backupNoticeOverlapMs`,
  `backupNoticesSince`, `backupStopV2` and `backupPassGateV2`, 4 in all.
- **Vectors**: `backup_plan.json` goes from 128 to 154 cases (17 `stop_ack`, 4 `gate_ack`, 4 `notices_since`,
  1 `notice_overlap`).

## [0.2.4] - 2026-11-08

Same API as v0.2.3, with `zip` moved from 8.6.0 to 9.4.1 (LD-0144). Nothing else changes in core: no item is renamed, retyped or
removed, and `src/` is untouched.

### Security

- `beebeeb-core` uses `zip` 9.4.1 (was 8.6.0) for `beebeeb_core::zip`. This clears RUSTSEC-2026-0429, -0367, -0368 and
  -0369, which are about `ZipArchive::extract` and `ZipStreamReader::extract`. Core writes archives (`ZipWriter`) and its
  tests read them back with `ZipArchive::new`; `git grep` finds no `.extract(` and no `ZipStreamReader` in this workspace,
  so none of the four was reachable here. A client that calls `zip` itself is not covered by that statement.
- A five-entry archive (incompressible, compressible, several chunks, empty, nested paths) written by `zip` 8.6.0 and by
  9.4.1 was byte-identical (342,915 bytes) in a one-off comparison on 2026-11-08; no test pins the bytes, so a later
  `zip` 9.x is not covered by that statement. No API of core changes, and `mixed_payloads_roundtrip` is new: the other
  zip tests use payloads of a few bytes.
- `zip` 9 adds `nix` 0.31 to core's tree (macOS and BSD targets only) and moves `typed-path` from 0.12 to 0.13. It also
  depends on `libc`, `windows-sys` 0.61 and `getrandom` 0.4, which core's lockfile already had. Every client's lockfile
  re-resolves when it takes this core.

## [0.2.3] - 2026-11-07

Additive on v0.2.2: the first pass's baseline and the pass gate when the notices could not be read (LD-0121, spec
`2026-11-06-backup-from-source-design.md` Amendment 12c, Guus 2026-11-07 20:45). No v0.2.2 API is renamed,
retyped or removed.

### Added

- **`beebeeb_core::backup`**: `first_pass_baseline(setup_at_ms, legacy_last_backup_ms)`, the `last_pass_at_ms`
  of a device with none under the new engine: the moment backups were set up on this device, or an upgraded
  device's last successful backup under the old mirror engine; with both known the earlier (a later baseline
  hides more notices, so the earlier never lets an emptied account fill up again); with neither, 0 (any
  removal notice stops the backup). `backup_pass_gate(notices, last_pass_at_ms, listing)` with
  `BackupPassGate::{Run { stopped }, CheckFailed}`: when the notices could not be read (`None`), the pass
  uploads nothing, turns nothing off, keeps `last_pass_at_ms` and retries at the next scheduled pass, showing
  `MSG_STOP_CHECK_FAILED` ("Couldn't check — will retry.").
- **Bindings**: uniffi `backup_first_pass_baseline`, `backup_pass_gate` (`BackupPassGate` enum),
  `backup_check_failed_words` (3); wasm `backupFirstPassBaseline`, `backupPassGate`, `backupCheckFailedWords` (3).
- **Vectors**: `backup_plan.json` 117 → 128 cases (+5 baseline, 5 gate, 1 check-failed words).

## [0.2.2] - 2026-11-07

Additive on v0.2.1: the rebuild's clock rule (LD-0123), why a backup stops (LD-0121, spec
`2026-11-06-backup-from-source-design.md` Amendments 12, 12a and 12b), and the CLI-login ECDH moved off
RUSTSEC-2026-0387 (task 2378). No v0.2.1 API is renamed, retyped or removed.

### Added

- **`beebeeb_core::backup`, rebuild (LD-0123)**: `RebuildClock { offset_ms, margin_ms }` with
  `RebuildClock::UNKNOWN` and `copy_is_newer`; `records_from_remote_with_clock(remote, entries, clock)`:
  a copy counts only when `uploaded_at_ms > modified_ms + offset_ms + margin_ms`, with no offset known
  the one-sided 10-minute floor (`REBUILD_FLOOR_MS`); `rebuild_clock_from_date(date_header, sent_at_ms,
  received_at_ms)` measures the offset from a listing response's `Date` header (margin
  `REBUILD_MARGIN_BASE_MS` 2 s + the round trip; any failure gives the unknown clock).
- **`beebeeb_types::backup` (LD-0121)**: `BackupStopReason` (`backup_deleted`, `erase_request`,
  `account_lapsed`, `inactive_cleanup`, `account_reset`, `unknown_removal`, `unknown`), `NOTICE_FILES_REMOVED`,
  `NOTICE_BACKUP_DELETED`, and `BackupNotice` (the `notifications` row's `type` and `data`, ids only).
- **`beebeeb_core::backup`, stop (LD-0121)**: `backup_stop(notices, last_pass_at_ms, listing)` (Amendment
  12's steps 1-4: a newer `files_removed` notice turns every backup off, folders present or not; else per
  backup a `backup_deleted` notice naming this device's folder (and, for a category, its folder); else a
  folder gone with no notice, `unknown`; else nothing),
  `parse_backup_notice`, `ReceivedNotice`, `StopListing`, `StopFolder`, `StoppedBackup`, and the words:
  `backup_stop_words(reason, device, folder)`, `MSG_STOP_ERASE_REQUEST`, `MSG_STOP_ACCOUNT_LAPSED`,
  `MSG_STOP_INACTIVE_CLEANUP`, `MSG_STOP_ACCOUNT_RESET`, `MSG_STOP_UNKNOWN_REMOVAL`, `MSG_BACK_UP_AGAIN`
  ("Back up again"): Amendment 12's six lines as drafted are final (Guus 2026-11-07 19:04, G6).
- **The seventh line (LD-0121, spec Amendment 12b)**: a `files_removed` notice whose reason this build does
  not recognise (a future reason, or none) stops every backup as `BackupStopReason::UnknownRemoval`
  (`"unknown_removal"`) with `MSG_STOP_UNKNOWN_REMOVAL`, "Your files were removed, so backups are off.",
  never the `unknown` row's "was deleted" words; `parse_backup_notice`, `BackupNotice::reason` and the uniffi
  and wasm `backup_notice_reason` / `backupNoticeReason` give `unknown_removal` for it.
- **Bindings**: uniffi `backup_stop`, `backup_notice_reason`, `backup_stop_words`, `backup_again_action`
  (4); wasm `backupStop`, `backupNoticeReason`, `backupStopWords`, `backupAgainAction` (4).
- **Vectors**: `backup_plan.json` 71 → 117 cases (+6 rebuild clock, 22 stop, 10 notice, 7 words, 1
  action); every rebuild case now carries its clock.

### Changed

- `records_from_remote(remote, entries)` (signature unchanged) now applies `RebuildClock::UNKNOWN`: with no
  offset known a copy must be more than 10 minutes newer than the entry's mtime. Desktop main already calls
  it (its rebuild after a reinstall or the G4 adoption, pinned at v0.2.1): after a pin bump, and until desktop
  passes a measured clock to `records_from_remote_with_clock`, a rebuild uploads again every copy made within
  10 minutes of its file's last change (the safe direction, but a re-upload of most auto-backed-up files).

### Security

- **`p256` 0.13 → 0.14** (task 2378, RUSTSEC-2026-0387): the CLI-login ECDH (`cli_auth`) now runs on
  `elliptic-curve` 0.14.3 / `crypto-bigint` 0.7.10, which removes the secret-dependent branches the
  advisory lists. Wire format unchanged: the SEC1 encodings, the ECDH X-coordinate and the HKDF key are
  byte-identical (`tests/cli_auth_vectors.rs` passes with its constants untouched, and now also pins both
  public keys, checked against the independent pure-Python generator `test-vectors/tools/make_cli_auth_vectors.py`).
  `CliEphemeralKey::generate()` keeps 0.13's non-zero scalar (`NonZeroScalar::generate()`, rejection
  sampling). `crypto-bigint` 0.5.5 stays in `Cargo.lock` through `opaque-ke` 4.0.1 → `voprf` 0.5.0 →
  `elliptic-curve` 0.13.8 (no published `opaque-ke`, 4.1.0-pre.2 included, moves off it); core's OPAQUE
  suites are Ristretto255 and compile none of its arithmetic, but `cargo audit` still lists the advisory
  until `opaque-ke` moves.
- `beebeeb-wasm` adds `getrandom` 0.4 with `wasm_js`: p256 0.14 draws its randomness through it.

## [0.2.1] - 2026-11-06

Additive: backup rules (`beebeeb_core::backup`), the vocabulary (`beebeeb_types::backup`) and the
filesystem pass (`beebeeb-backup`). No v0.2.0 API changes. LD-0113, spec
`2026-11-06-backup-from-source-design.md` §4.

### Added

- **`beebeeb_types::backup`**: `SystemRole` (wire `"backups_root"`), `PROTECTED_FOLDER_ERROR`
  (`"protected_folder"`), `BACKUPS_ROOT_UNCLAIMABLE_ERROR` (`"backups_root_unclaimable"`),
  `ORIGIN_HEADER` (`"X-Beebeeb-Origin"`) and `ORIGIN_BACKUP` (`"backup"`), the header every request of
  a backup pass carries (spec Amendment 8; the server ignores it until phase 2), `Category` (keys and
  display names) and `Platform`.
- **`beebeeb_core::backup`** (pure: no I/O, no clock, no network):
  - layout: `ROOT_NAME` `"Backups"`, `MANIFEST_NAME` `".device.json"`, `backup_rel_path`;
  - protection (spec Amendments 7 and 8; a backup is written by its device's own backup and by
    nothing else): `Mutation` (`trash`, `delete`, `rename`, `move`, `create`, `write`; a move checks
    the row with `Move` and the destination folder with `Create`), `BackupPosition` (`Root`,
    `DeviceFolder`, `Manifest`, `CategoryFolder`, `Inside`, `Outside`) with
    `BackupPosition::at_depth(depth, name)` and `is_hidden_backup_item` (a device folder's manifest,
    never listed), and three rules with one set of words (`MSG_DELETE`, `MSG_MOVE`, `MSG_RENAME`,
    `MSG_MANAGED_IN_APP`, `MSG_READ_ONLY`, and `MSG_BADGE` "Read-only", the badge every client shows
    on the Backups root; Guus, "keep it Backups and just add a read-only badge"): `check_app_mutation` (web, desktop in the app,
    iOS, the CLI: the root and a device's manifest refuse everything; under the root a backup can be
    trashed or deleted and nothing else changes), `check_drive_mutation`
    (Explorer, Finder, the iOS Files app: nothing at or under the root changes; the root's words,
    then `own_backup_refusal` for the device's own active backups, then the rest) and
    `check_root_mutation` (the server's phase-1 rule: the root is never trashed, deleted, renamed or
    moved). The backup pass never goes through these rules;
  - skip rules: `skip_reason`, `SkipReason` (OS junk, library bundles, links, not-local entries
    and `.icloud` stubs, plus the client-set `Locked` and `TooLarge`, and the walk's `TooDeep`,
    `Unreadable` and `Excluded`);
  - device folders: `device_folder_name`, `device_id_from_machine_id` (label
    `beebeeb/backup-device-id/v1`), `find_device_folder` (by manifest id, legacy desktop adoption,
    create; an unreadable manifest is not mine and not adoptable). A device id is a string identity:
    a UUID or an iOS legacy id carried forward verbatim;
  - the manifest: `DeviceManifest`, `parse_manifest`, `serialize_manifest` (a real iOS manifest
    round-trips; unknown fields are kept, a folder entry's own included; only a document that is
    not a JSON object is unreadable: a bad field takes its default and a bad `folders` entry is
    dropped alone; a known field always wins over kept text of its name);
  - the root: `resolve_root` (use the flagged root, claim the oldest live `Backups`, or create) and
    `plan_merge` (legacy duplicate roots, depth unbounded, keep-both on a clash);
  - the pass planner: `plan_pass(entries, records, live_remote, live_remote_complete, unseen, held,
    budget)` (new, changed, unchanged, gone, unique moves, the budget, removed elsewhere only from a
    complete listing, a record missing from an incomplete listing is unknown and its work waits (a
    move whose signature an unknown record shares waits too), a changed file whose remote copy is
    gone uploads as new, a record whose copy is live again is held again, a record under an unseen
    key (raw, or by its folded key, NFC and case, when no entry has its exact key) is untouched,
    held keys skipped and not charged, the first upload always fits (`max_uploads` 0 counts as 1);
    each upload carries the paired `record_key` and, for a change, the `remote_id` it versions;
    each record to mark removed elsewhere is a `RecordRef` (key and remote id) for a
    compare-and-set), `folder_presence`,
    `records_from_remote` (exact key first, then the normalised key when unique), `normalize_key`,
    and the key helpers `file_name`, `parents` and `fold_name`;
  - custom folders: `custom_category_name` (safe like a device folder, never equal to a fixed
    category or another custom folder: ` (2)`, ` (3)`; at most 200 bytes with the suffix and a
    reserved stem's `_`, the base is cut, never the suffix) and `category_folder_name`.
- **`beebeeb-backup`** (new crate, for desktop and the CLI): `walk_source(root, exclude)` (never
  opens a file, never follows a link, never descends into what is not local (the backed-up folder
  itself included: a not-local root is one skip, never listed) or into an excluded
  path such as the client's own sync root; attributes from the directory listing only; a folder is
  listed whole or reported unreadable; depth cap 64; a root whose path holds `..` is
  `InvalidInput`), `fingerprint`, `attrs_of`, and
  `run_pass(host, root, exclude, category, budget)` over the `BackupHost` trait the client
  implements (it re-reads an entry whose listing differs from its record, checks what can fail
  before it changes anything, and on Windows and macOS never creates a folder that differs from
  an existing one only in case or normalisation). `BackupHost::mark_removed_elsewhere` is
  compare-and-set on the key and remote id the pass read: a record a finishing upload rewrote
  meanwhile is left alone. `BackupHost::put_record` (after a move) re-keys the record the pass read,
  keeping the fields stored now, or stores the moved record when no record names that remote file
  any more; it answers whether it stored, and a move it left alone counts as deferred. Every request a host makes for a pass carries
  `ORIGIN_HEADER: ORIGIN_BACKUP`.
- **Bindings**: uniffi `backup_*` (16 functions, among them `backup_check_root_mutation`,
  `backup_check_app_mutation`, `backup_check_drive_mutation`, `backup_position_at_depth`,
  `backup_is_hidden_item`, `backup_root_badge`, `backup_root_name` and `backup_origin_header`;
  every unknown string is `InvalidInput`) and wasm `backupCheckRootMutation`,
  `backupCheckAppMutation`, `backupCheckDriveMutation`, `backupPositionAtDepth`,
  `backupIsHiddenItem`, `backupRootBadge`, `backupProtectionMany`, `backupParseManifest` (8).
- **Vectors**: `test-vectors/consolidation/backup_{protect,device,root,plan}.json` (163, 57, 21 and
  71 cases, counted with `python3 -I -c "import json,sys; [print(p, len(json.load(open(p))['cases'])) for p in
  sys.argv[1:]]" test-vectors/consolidation/backup_*.json`; `check-backup-vectors-generated.sh` guards them in
  CI), run by `cross_client_vectors`, with independent Python generators in
  `test-vectors/tools/make_backup_*_vectors.py`.

## [0.2.0] - 2026-11-06

### Breaking and behaviour changes

- **`owned_keys::resolve_owned_key` signature changed** to six arguments: takes `name_encrypted`
  and, for a plaintext-named file, `first_chunk`. The old five-argument form and `foreign_added`
  are removed; the id class now decides. `ResolvedOwnedKey` gains `name` and `write_target`.
  Callers must add the two new arguments.
- **`kdf::wrap_owner_file_key` / `unwrap_owner_file_key` now refuse a non-foreign id.** L8 is
  adoption-only. Any call that passes an owner id must switch to a foreign id.
- **`ChunkDecryptor::{from_reader, for_push, for_push_with_file_key}` and several decrypt helpers
  now require `ExpectedChunkFormat` and/or the file id.** Affected: `encrypt::decrypt_chunks_to_file`,
  `encrypt::decrypt_contiguous_to_file`, `file_encrypt::decrypt_chunks_to_file`,
  `zip::ZipEntry` (new `chunk_format` field), `beebeeb_upload::{decrypt_downloaded_bytes,
  download_and_decrypt_file, DownloadClient::download_and_decrypt}`, and the UniFFI/WASM
  equivalents. `chunk_stream::open_chunk` now also takes the version id. Callers must read
  `ExpectedChunkFormat` from the file's authenticated metadata (`decrypt_name_metadata`) and
  pass it on every decrypt call.
- **`encrypt::decrypt_file_metadata[_with_key]`** (new, for files): a plaintext `name_encrypted`
  is now refused. Use `decrypt_name_metadata` for folders; use `decrypt_file_metadata` for files.
- **`DownloadPlanner` verdict ordering changed**: a file keeps the strongest verdict received
  (`Corrupt` > `Terminal` > `Restart` > `ApiForFile`); once set, a weaker answer can no longer
  override it. Stale, repeated, or out-of-order window answers no longer downgrade a verdict.
- **Discovery authorization answers (401/403) no longer count toward the routing-failure budget**
  and no longer disable direct discovery for ten minutes on repeated refusals. Reauthentication
  leaves cached discovery and real transport failures unchanged.

### Added

- Range reads for streaming hydration (LD-0105, core PR #71): `chunk_stream::RangeOpener`
  opens one authenticated frame at any index under the file's one geometry and version id;
  `direct_transfer::range::RangePlanner` grants windows at any start (chunk 0 first, then
  demands, then read-ahead), aging out idle grants without spending renewals; `range_session`
  in `beebeeb-transfer` hands each authenticated 4 KiB piece to the system; `RangeLessor`
  bounds the shared memory budget: at most four sessions hold a lease at once; together their
  ciphertext in flight is at most max(256 MiB, k × (chunk_size + 28)) for k active sessions,
  plus one plaintext chunk per session (256 MiB at 32 MiB chunks, up to 1 GiB at 128 MiB chunks). New test vectors:
  `test-vectors/direct_range.json`, generated and drift-guarded in CI.
- `beebeeb-transfer`, the L2 driver crate for direct S3 downloads (task 2173, plan K2):
  `download()` drives core's `DownloadPlanner` over any `DirectIo` transport (API calls,
  bounded storage GETs, the pinned per-chunk route, injected sleep and clocks), decrypts
  chunks in order through `ChunkDecryptor`, writes plaintext only after a chunk authenticates,
  and reports `Done(stats)` or `UseApi(reason)`. Body checks go through core's `StorageBody`
  (`from_head` / `push` / `finish`); a signed URL never reaches an event, error or `Debug`
  string; `DirectStore` shares discovery and breaker health per `(api_base, account_id)`.
  `test_support::ScriptedIo` and a conformance suite (`test-support` feature) check a
  transport's redirect, cookie, credential, idle/total timeout and bounded-body behaviour
  in-process. No tokio or reqwest in normal dependencies.
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
- Link labels and guest actor names (task 2275, L16): `kdf::wrap_link_label` /
  `unwrap_link_label` seal a link's display label to the master key under
  `HKDF-SHA256(master, "beebeeb-link-label-v1" || share_id)` with the same string as AAD; the label
  is NFC and 1..40 Unicode scalar values after NFC. `kdf::seal_folder_actor_name` /
  `open_folder_actor_name` seal a guest's name under
  `HKDF-SHA256(folder key, "beebeeb-folder-actor-name-v1" || root_id)` with the same string as AAD.
  Both sides of the actor name apply ONE rule, `kdf::sanitize_actor_name`, and the writer seals its
  result, so core never seals a name its own opener refuses: (1) NFC; (2) strip every `Cc`
  character and U+00AD, U+061C, U+180E, U+200B, U+200E, U+200F, U+2028-U+202E, U+2060-U+2064,
  U+2066-U+206F, U+FEFF, U+FFF9-U+FFFB, while keeping U+200C ZWNJ, U+200D ZWJ, the variation
  selectors and the tag characters U+E0020-U+E007F (Persian and Indic spelling, emoji ZWJ
  sequences and subdivision flags need them); (3) NFC again; (4) refuse a leading combining mark;
  (5) 1..64 scalars, counted after steps 1-4; (6) refuse a visibly blank name, one with no
  character that is neither whitespace nor an invisible filler (Hangul fillers, U+2800, U+034F,
  the Mongolian and other variation selectors, Khmer inherent vowels, U+1D173-U+1D17A, ZWNJ, ZWJ,
  the tags, and every other Default_Ignorable_Code_Point that is not stripped). The writer refuses
  with `InvalidInput`; the openers normalize instead of refusing non-NFC plaintext, and refuse
  anything else they cannot display with `Decryption`; a non-16-byte id is `InvalidInput`. The
  actor-name envelope is a JSON text value with exactly the keys `cipher_suite`, `nonce` and
  `ciphertext` (all required, none `null`, no other or repeated key); key order and JSON
  whitespace are free, so a hop that re-encodes the JSON keeps it openable.
  `kdf::open_legacy_child_key` is the one legacy unbound child opener (60-byte frame, no AAD)
  and refuses a 32-byte plaintext that is valid UTF-8; a genuine random legacy child key that
  happens to be UTF-8 (about 2^-30) is refused and reads as a wrong key (accepted L9 residual,
  recorded on the function). WASM `wrapLinkLabel` / `unwrapLinkLabel` / `sealFolderActorName` /
  `openFolderActorName` / `openLegacyChildKey`; UniFFI `MasterKeyHandle.wrap_link_label` /
  `unwrap_link_label` and `FileKeyHandle.seal_folder_actor_name` / `open_folder_actor_name` /
  `open_legacy_child_key`. Test vectors are version 16 (`link_label_v1`, `folder_actor_name_v1`,
  `legacy_child_refusal_v1`); version 14 is main's `item_ids` set alone, and 15 is not used (it
  named an earlier draft of these vectors on the unmerged branch). Vendored copies must be
  refreshed to 16: web `test/core-vectors-kat.test.ts`, mobile `CoreVectorsKATTests.swift` and
  `CoreVectorsKATTest.kt`.
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

- Discovery authorization answers (401/403) no longer consume or extend the routing-failure
  budget. Reauthentication leaves cached discovery and real transport failures unchanged;
  repeated authorization refusals no longer disable direct discovery for ten minutes.
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

- Chunk format v2 (task 1908): core now reads chunk format v2. File-content frames carry position
  as AES-GCM associated data — `"beebeeb/chunk/v2" || len(file_id) || file_id || version_id(12) ||
  chunk_index || is_last` (STREAM construction) — and are sealed under a dedicated chunk subkey
  `HKDF-SHA256(file_key, "beebeeb/chunk/v2/key")` that no other blob type uses. `version_id` is
  the random nonce of the upload's frame 0, so frames of two uploads (versions) of one file id
  cannot be mixed. v1 frames, which every client still writes, carry no associated data, so a
  malicious server can reorder, duplicate, drop, truncate or splice them undetected. Same frame layout and sizes;
  the server is unaffected. `chunk_stream::WRITE_FORMAT` stays `V1Legacy`: every client still
  WRITES v1 until all clients' read paths are on this core; flipping it is a separate, gated
  release (task 1908). Files written today still carry no position binding.
- Every file-content reader now REQUIRES an `ExpectedChunkFormat` taken from the file's
  encrypted metadata (`encrypt::decrypt_name_metadata[_with_key]`): `V2` accepts only v2 frames,
  so a server can no longer pass a same-key no-AAD blob (encrypted name, thumbnail) off as a
  one-frame v1 file; `Unrecorded` (metadata without a format: files from before the switch) lets
  frame 0 decide. Readers reject out-of-order frames, frames from another upload, frames after
  the last chunk, and fail at `finish()`/EOF when a v2 file ended early. A zero-frame body is now
  an error (it used to decrypt to an empty file). Uploads record the format with
  `encrypt::encrypt_name_with_chunk_format` (`"chunk_format": 2`); `encrypt_name` output is
  unchanged.
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
