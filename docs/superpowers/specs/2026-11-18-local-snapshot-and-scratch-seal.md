# Local recovery snapshot and per-session scratch seal (design note)

Status: reviewed 2026-11-18, the review's blocking and recommended items are folded in below; implemented as written. Module: `beebeeb_core::local_seal` (new, `beebeeb-core/src/local_seal.rs`).
Context: the native office editor (contract: "Native office editor", 2026-11-12, sections 5.4 and Q3) must keep an
unsaved document recoverable after a crash or power loss, and must hold large documents and a staged save payload
outside plaintext files. Crypto lives in core; the app only calls it. This note wins over the working names in the
epic's "Core" interface line.

## 1. Recovery snapshot

An unsaved document, sealed at rest on this device, openable after a crash or power loss by the same account only.
The app holds the plaintext in memory, calls core, and writes the returned bytes. The helper never sees a key.

### 1.1 Decision on Q3: a dedicated local label, not the upload format

The contract's recommendation is the upload format (a fresh file key, wrapped by the account key, chunk format v2).
I recommend against it, for four reasons:

- A v2 blob is only valid with a version commitment (`VersionCommitment`: frame 0's nonce plus a counter above the
  server's high-water mark, see `check_version_counter`) and a metadata record that names the format. The counter is
  decided at upload time, so a blob sealed minutes earlier cannot honestly claim one. "Upload it unchanged" does not
  hold without re-sealing.
- A snapshot means "unsaved edits against `base_version`". Uploading it as a version would bypass the user's explicit
  save and the conflict check.
- The writer (`ChunkEncryptor::for_push`) and the owner key wrap (`wrap_owner_file_key`) are built for one upload with
  a server-dictated chunk plan; a snapshot every 2 to 10 seconds would mint a wrapped key and a version id each time.
- Reusing the file key tree (`derive_file_key`) would put a local blob under the same key as the file's content. A
  new purpose gets a new `info`, which is the rule in `CLAUDE.md` ("a new derivation gets a new info string").

So: a new derivation with new labels (all `v1`), no change to any existing format, label or AAD. If Guus prefers the
upload format anyway, sections 1.2 to 1.6 become a thin wrapper over `ChunkEncryptor` and the open question in
section 6 (version counter) must be answered first.

### 1.2 Key derivation

`snapshot_key = HKDF-SHA256(salt = none, ikm = master key, info = SNAPSHOT_KEY_LABEL || file_id)`, built with the
same pattern as `derive_file_key` (an internal `derive_snapshot_key`). The key is 32 bytes, `Zeroizing`, never
exported. It is a local key, not a file key: the type `FileKey` is only the carrier `seal_raw_with_aad` takes, and
the function that makes it is module-private, so no other module can pass it where a content key belongs.
`file_id` is the canonical item id text (UTF-8). Both owner (`O`) and foreign (`F`) ids are accepted (a document can
sit in either kind of row); a non-canonical id is `InvalidInput` (`item_class` decides), never treated as a
different file. The master key is the account key that exists only while unlocked, so a locked or signed-out app
cannot open a snapshot. Every plaintext buffer core holds in this module is `Zeroizing`.

New labels, each to be added to `LABELS` in `label_table_tests.rs` (the completeness test fails otherwise):

| name | bytes | slot | with |
|---|---|---|---|
| `SNAPSHOT_KEY_LABEL` | `beebeeb-local-snapshot-v1` | InfoWithId | master key (id appended) |
| `SNAPSHOT_AAD_LABEL` | `beebeeb-local-snapshot-aad-v1` | Aad | the snapshot key |
| `SCRATCH_KEY_LABEL` | `beebeeb-scratch-chunk-key-v1` | InfoWithId | the session scratch key (`scratch_id` appended) |
| `SCRATCH_AAD_LABEL` | `beebeeb-scratch-chunk-aad-v1` | Aad | the scratch chunk key |

No label is a prefix of another HKDF `info` label; no entry is needed in `CROSS_SLOT_PREFIX_PAIRS` (the test
confirms). The four labels are distinct from all 55 existing ones, so `LABELS.len()` becomes 59 (the assert in
`label_table_tests.rs` is changed to 59 in the same commit). A future incompatible change uses `v2` labels and a new format byte, never a reinterpretation.

### 1.3 Seal and AAD

One frame: `nonce(12, random per seal) || AES-256-GCM(snapshot_key, nonce, plaintext, AAD) || tag(16)`, sealed with
the existing `seal_raw_with_aad` / `open_raw_with_aad` (tag verified before any plaintext is produced). Random
96-bit nonces under one key (account x file) stay far below the birthday bound (a seal every 2 seconds for a year is
under 2^25).

`AAD = SNAPSHOT_AAD_LABEL || u32be(len(file_id)) || file_id || i64be(base_version) || i64be(saved_at) || u8(kind) ||
u8(header_version)`.

`base_version` is the file version the edits start from, `saved_at` is unix seconds, `kind` is 1 docx, 2 xlsx, 3 pptx
(the helper's `EditKind`; an unknown value is `InvalidInput`). All three are bound, so a blob cannot be re-labelled
(a snapshot of file A is not file B's; a changed base version or time fails the tag).

Size: a snapshot is one frame, so the whole document is in memory already (the host holds it from the save
handshake). `MAX_SNAPSHOT_BYTES` is 256 MiB (equal to `MAX_CHUNK_SIZE`, checked by a compile-time assert in core). The app's
own cap `MAX_SAVE_BYTES` is tied to it: the engine adds `const _: () = assert!(MAX_SAVE_BYTES <= MAX_SNAPSHOT_BYTES)`
so a raised save cap cannot outgrow the snapshot. Larger input is `InvalidInput`. AES-GCM's per-message limit is not
close.

### 1.4 On-disk framing

```
offset  len  field
0       4    magic "BBSN"
4       1    header_version = 1
5       1    kind
6       8    base_version (i64 big-endian)
14      8    saved_at (i64 big-endian)
22      12   nonce
34      n+16 AES-256-GCM ciphertext and tag
```

The header carries `kind`, `base_version` and `saved_at` in clear (they are not secret: no name, no content; the app
may show "unsaved changes from 14:32" without a key) and the AAD repeats them, so editing the header fails the tag.
`base_version` and `saved_at` must be `>= 0` (`InvalidInput` otherwise, at seal and at open). The file id is NOT stored in the blob: the caller supplies it (it names the blob's file and directory), so a
blob moved to another file's slot does not open. `open` returns the meta it authenticated, and that is the only meta a decision may use: `peek_snapshot_meta` reads
the header without a key and without authentication, so its result is for display only (a restore prompt line) and
never for deciding what to restore, replace or delete. The magic, version and kind are checked first (`InvalidInput`);
an unknown `header_version` is an error, never a fallback; then the tag (`Decryption`).

Per-byte result of a one-bit edit of the header (vector-tested): bytes 0 to 3 (magic) and byte 4 (version) give
`InvalidInput`; byte 5 (kind) gives `InvalidInput` when the new value is not 1 to 3 and `Decryption` when it is;
bytes 6 to 21 (`base_version`, `saved_at`) give `Decryption` (or `InvalidInput` if the edit makes a value negative);
bytes 22 to the end (nonce, ciphertext, tag) give `Decryption`.

### 1.5 Atomic replace (engine, not core)

Core is I/O-free for this module: it returns and takes bytes. The engine writes one blob per open document in a
per-account folder under the app's data folder: write `<id>.bbsnap.tmp` in the same folder (0600 on Unix), fsync the
file, `rename` over `<id>.bbsnap`, fsync the folder. The previous blob is replaced only by that rename, so a crash
leaves the old or the new one, never half. A leftover `.tmp` is deleted at startup, never opened. The engine opens a
new blob (or at least the header) after writing it before it drops the previous snapshot of the editor's memory.

Windows: the folder is per user, under `LocalAppData` (never `Roaming`, so it does not sync to another PC), with an
ACL that grants only that user. The replace is `MoveFileExW(tmp, final, MOVEFILE_REPLACE_EXISTING |
MOVEFILE_WRITE_THROUGH)`. A rename can fail while an antivirus scanner or the indexer holds the file: retry a few
times with a short back-off, and if it still fails keep the old blob (never delete it first) and report a failed
snapshot to the editor, which keeps the document in memory and tries again at the next tick.

Startup cleanup (deleting leftover `.tmp` files and old scratch files) runs only while the engine holds the
single-instance lock of the app data folder, or each process works in its own scratch folder named by its process
id and a lock file it holds, and cleanup removes only folders whose lock is free. Two instances can therefore never
delete each other's live files. The engine owns this rule; core is I/O-free here.

Restore: a snapshot carries `base_version`. If the file's version on the server is above `base_version` at restore
time, the restore goes through the conflict path (keep both as a copy, or ask the user); it never overwrites a newer
saved version.

### 1.6 What sign-out wipes

Delete (best effort, then verify absent) every `.bbsnap` and `.bbsnap.tmp` of the signing-out account, on discard and
on sign-out, as contract section 5.4 says. A save deletes the file's snapshot only after the server confirmed the new
version (the commit response arrived); a failed or interrupted save keeps the snapshot. After a restart the engine
never resumes a save from scratch files: a snapshot is the only recovery source. No key is ever stored, so a lock or a leftover blob after a crash
of the wipe is unreadable without the master key. The engine must delete only its own account's folder; a blob of
another account on the same PC is never opened (wrong key gives `CoreError::Decryption`) and never deleted by this
account's sign-out.

## 2. Scratch seal

A random key per signed-in account session, in memory only, for (a) a large document the host spills out of memory
and (b) the staged save payload before upload. The engine creates one `ScratchKey` when an account session starts
and drops it on sign-out, on account switch and on lock; at each of those points it also deletes that session's
scratch files. A restart makes every old scratch file unreadable by design; the engine deletes leftovers at start
under the single-instance rule of section 1.5 (no recovery from scratch: that is what the snapshot is for).

### 2.1 Key

`ScratchKey::generate() -> Result<ScratchKey, CoreError>`: 32 bytes from the OS CSPRNG (the same source as
`FileKey::generate`), never derived from the master key or any account key. It is not `Clone`, `Debug` prints
`ScratchKey(..)`, there is no `as_bytes`, `to_bytes`, `Serialize` or `From<[u8; 32]>` in a shipped build (a
`cfg(test)` / `test-support` constructor exists for vectors only, like `with_vector_nonces`). It is zeroized on drop.
The sealing key is per file: `file_key = HKDF-SHA256(salt = none, ikm = scratch_key, info = SCRATCH_KEY_LABEL ||
scratch_id)` (`derive_file_subkey` with that info), so the raw random key never seals directly and every scratch file
has its own key and its own nonce space.

### 2.2 Stream format

A scratch file is a header plus fixed-size frames. `ScratchWriter` takes a fresh random 16-byte `scratch_id` (the
per-file id), a `purpose: u8` (1 spill, 2 staged save) and a chunk size (default 1 MiB, `MIN_SCRATCH_CHUNK..=MAX_CHUNK_SIZE`; `MIN_SCRATCH_CHUNK` is 64 KiB, so a 4 GiB file
is at most 65 536 frames).

```
0    4   magic "BBSC"
4    1   header_version = 1
5    1   purpose
6    4   chunk_size (u32 big-endian)
10   16  scratch_id
26   ...  frames: nonce(12) || ciphertext(chunk_size, last may be shorter or empty) || tag(16)
```

`AAD(frame) = SCRATCH_AAD_LABEL || header (the 26 header bytes) || u32be(index) || u8(is_final)`. Binding the header
binds the file id, purpose and chunk size to every frame. The index binds order (reorder, duplicate and splice from
another scratch file fail). The final flag binds the end: the writer holds back one chunk and seals the last one as
final, so a file whose last frame was cut off fails (the last present frame was sealed as non-final and does not open
as final), and extra frames appended after the final one are rejected (the reader requires EOF after the final frame).
Exact-multiple rule: the final frame carries 1 to `chunk_size` plaintext bytes, so a document whose length is an exact
multiple of `chunk_size` ends in one full final frame and never in an extra empty one; only the empty document is a
single final frame of zero plaintext bytes. This makes the file for a given input, key and nonces deterministic. The index is a `u32`; passing `u32::MAX` frames is an
error (checked arithmetic). A file is also bounded by `MAX_SCRATCH_BYTES` (4 GiB; a write past it is `InvalidInput`).

### 2.3 Reader contract

`ScratchReader<R: Read>` implements `Read` and decrypts one frame at a time, reading ahead one byte to learn whether
a frame is the last. It follows the same rule as the chunk readers in core: plaintext of a frame is released only
after that frame authenticated, but whole-file integrity (truncation, trailing bytes) is known only at EOF, so a
consumer that publishes the payload MUST NOT use any of it until a full read ended in `Ok`, and discards all of it on
any `Err`. For the staged save the engine therefore runs `verify_scratch` first (one full authenticating pass that
returns the plaintext length and the `scratch_id`, and keeps nothing) and then starts the upload pass with a
`ScratchReader` built with that `scratch_id` as the expected id; a file swapped between the two passes (another valid
file of the same session) has another id and fails with `Decryption` at construction. The upload commits only after
pass 2 ended in `Ok` (the reader reached the final frame and EOF), and abandons the upload on any `Err`. Frames are
read into a buffer that grows with the bytes actually present, so a hostile `chunk_size` in a header allocates
nothing beyond the file; the bounds check on the header happens first.

## 3. API

All in `beebeeb_core::local_seal`. No uniffi or wasm export this round (desktop-only; the engine links core directly).

```rust
pub struct SnapshotMeta { pub base_version: i64, pub saved_at: i64, pub kind: u8 }

pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;

pub fn seal_recovery_snapshot(master: &MasterKey, file_id: &str, meta: &SnapshotMeta, plaintext: &[u8])
    -> Result<Vec<u8>, CoreError>;
pub fn open_recovery_snapshot(master: &MasterKey, file_id: &str, sealed: &[u8])
    -> Result<(SnapshotMeta, Zeroizing<Vec<u8>>), CoreError>;
/// Reads and checks only magic, version and header fields; opens nothing, needs no key.
/// UNAUTHENTICATED: for display only. Decisions use the meta `open_recovery_snapshot` returns.
pub fn peek_snapshot_meta(sealed: &[u8]) -> Result<SnapshotMeta, CoreError>;

pub struct ScratchKey { /* private */ }
impl ScratchKey { pub fn generate() -> Result<Self, CoreError>; }

pub const DEFAULT_SCRATCH_CHUNK: u32 = 1024 * 1024;
pub const MIN_SCRATCH_CHUNK: u32 = 64 * 1024;
pub const MAX_SCRATCH_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const SCRATCH_PURPOSE_SPILL: u8 = 1;
pub const SCRATCH_PURPOSE_STAGED_SAVE: u8 = 2;
pub struct ScratchWriter<W: Write> { /* private */ }
impl<W: Write> ScratchWriter<W> {
    pub fn new(key: &ScratchKey, out: W, purpose: u8, chunk_size: u32) -> Result<Self, CoreError>;
    pub fn scratch_id(&self) -> [u8; 16];
    pub fn finish(self) -> Result<(W, u64 /* plaintext bytes */), CoreError>; // seals the final frame
}                                                  // impl Write: buffers, seals full non-final chunks
pub struct ScratchReader<R: Read> { /* private */ }
impl<R: Read> ScratchReader<R> {
    /// `expected_id`: the id `verify_scratch` returned (or the writer reported); another id is `Decryption`.
    pub fn new(key: &ScratchKey, input: R, expected_purpose: u8, expected_id: &[u8; 16]) -> Result<Self, CoreError>;
}                                                  // impl Read
pub struct VerifiedScratch { pub plaintext_len: u64, pub scratch_id: [u8; 16] }
pub fn verify_scratch<R: Read>(key: &ScratchKey, input: R, expected_purpose: u8) -> Result<VerifiedScratch, CoreError>;
```

Errors: `CoreError::Decryption` for any tag failure, wrong key, truncation, reorder or trailing data (one error, no
oracle on which); `InvalidInput` for a bad header (magic, version, a purpose that is not 1 or 2, a chunk size outside the bounds), size,
id or kind (a known purpose that is not the expected one is `Decryption`); `Io` for the sink or source (inside
`Read`/`Write` it surfaces as `io::Error` wrapping the same). Only purposes 1 (spill) and 2 (staged save) exist; any other value is `InvalidInput` at the writer and the reader. A
dropped `ScratchWriter` without `finish` leaves a file
that fails to open (it has no final frame), by design. The plaintext returned by `open_recovery_snapshot` is `Zeroizing`.

Not exported to uniffi or wasm: every item above, `ScratchKey` in particular (no key bytes may cross an FFI
boundary), and `scripts/check-doc-symbols.sh` / the binding crates get no entry. A test greps `beebeeb-uniffi` and
`beebeeb-wasm` sources for `local_seal` and fails if one appears.

## 4. Test-vector plan

New `test-vectors/local_seal.json`, checked by `scripts/check-test-vectors.sh` and a `local_seal` unit module:

- Snapshot: fixed master key, file id, meta and nonce (a `cfg(test)` / `test-support` seam like
  `ChunkEncryptor::with_vector_nonces`): derived key hex, AAD hex, header hex, full sealed blob hex, for an empty, a
  one-byte and a 100-byte plaintext. Open must return the same bytes.
- Scratch: a fixed key, scratch id and nonces (same seam), chunk size `MIN_SCRATCH_CHUNK`: header, per-frame AAD and
  the file for 0, 1, 65 535, 65 536, 65 537 and 196 608 bytes (the empty, short-final, exact-multiple and
  multi-frame edges, including the exact-multiple rule of section 2.2). Plaintext is a stated byte pattern; the two
  smallest files are listed in full, the larger ones by length, frame nonces and SHA-256 of the file. An independent
  Python implementation of this note writes the file and `scripts/check-test-vectors.sh` fails on any difference.
  Unit tests with a test-only seam that lowers the chunk floor cover the same edges at chunk size 16.
- Negative cases, each must fail with `Decryption` (unless a case says `InvalidInput`) and release no final plaintext: flip each header byte (the expected error per byte is in section 1.4: magic, version and an invalid kind give
  `InvalidInput`, the rest `Decryption`), flip one ciphertext bit, wrong master key, wrong file id, wrong
  `base_version`/`saved_at`/`kind`, both an `O` and an `F` id seal and open; scratch: drop the last frame, drop a middle frame, swap two frames, duplicate a frame, append a
  frame after the final one, splice a frame from a second scratch file, wrong key, wrong purpose, chunk-size field
  edited, a reader built with another file's `scratch_id` (`Decryption`), one-bit edits of every scratch header byte
  (magic, version, an unknown purpose and an out-of-range chunk size give `InvalidInput`); writer chunk size below
  `MIN_SCRATCH_CHUNK` and above `MAX_CHUNK_SIZE`, an unknown purpose; oversize snapshot input; `ScratchKey` has no
  serialise path (doc `compile_fail` tests: no `Clone`, no `Serialize`, no byte accessor; `Debug` shows no bytes).
  A source grep test fails if `local_seal` appears in `beebeeb-uniffi` or `beebeeb-wasm`.
- `label_table_tests.rs` lists the four labels (section 1.2) and counts 59; a test that the snapshot key differs from
  `derive_file_key` for the same id, and that a snapshot blob does not open under the file key.
- A scratch file of one session key does not open under another `ScratchKey`; a file does not open under another
  file's derived key (per-file key).
- Nonce freshness: two seals of the same input differ (as `shipped_name_writers_draw_a_fresh_nonce_each_call` does).

## 5. Threat model

| Threat | Result |
|---|---|
| Stolen disk or backup of the data folder | Snapshots are AES-256-GCM under a key from the master key, which is not on disk; scratch files are under a key that died with the process. Header leaks kind, base version, saved-at and the exact plaintext size (blob length is plaintext + 50: 34 header
bytes and the 16-byte tag), and the `<id>.bbsnap` file names leak the server item ids of documents with an unsaved
snapshot (accepted, listed: an id is a random UUID, meaningless without the server). No plaintext file exists. |
| Another account on the same PC | A different master key gives a different snapshot key: `Decryption`. The folder is per account and sign-out deletes only its own. Scratch is per account session and 0600; another account's session has another random key, and the key and the files
are dropped on sign-out, switch and lock. |
| Truncation | Snapshot: one frame, a cut blob fails the tag. Scratch: the final flag is bound, so a cut file fails at the last present frame; trailing data after the final frame fails. |
| Reorder, duplicate or splice of frames | Index and `scratch_id` are in every frame's AAD: fail. |
| Replace a blob with another file's blob | `file_id` is in the AAD and not in the blob: fail. |
| Replay of an older snapshot of the same file | Not detectable by core (a valid old blob is valid). The engine keeps one blob per file, replaced atomically, shows `saved_at` in the restore prompt ("changes from 14:32"), and the user chooses Restore or Discard; the worst outcome is losing recent unsaved edits, never a silent overwrite of a saved version. Accepted, noted. |
| A snapshot uploaded or opened as file content | The key and AAD are purpose-bound; it never opens as a v2 frame and no v2 frame opens as a snapshot. |
| Nonce reuse | Random 96-bit nonces; per-key volume is far below 2^32 (section 1.3). Scratch: fresh random key per session. |
| Two app instances | Startup cleanup runs only under the single-instance lock (or per-process folders with a lock file), so one instance never deletes another's live files (section 1.5). |
| Scratch file swapped between verify and upload | The reader is built with the id `verify_scratch` returned: another file fails with `Decryption`; the upload commits only after pass 2 ended in `Ok`. |
| Memory remnants | Keys and returned plaintext are `Zeroizing`; the key types are not `Clone` and never in `Debug` or errors. |

## 6. Decisions (the former open questions)

1. Q3: a dedicated local label, not the upload format (decided in the review of 2026-11-18). Labels are distinct from
   all 55 existing ones, no prefix clash.
2. The atomic file replace stays in the engine for now, with a test that kills the process between the steps.
3. `MAX_SNAPSHOT_BYTES` is 256 MiB, tied to the app's `MAX_SAVE_BYTES` by a compile-time assert (section 1.3);
   `MAX_SCRATCH_BYTES` is 4 GiB, safe because of the per-file key and the 64 KiB chunk floor.
4. `saved_at` in clear is accepted (display only).
5. Purposes 1 and 2 now; an unknown purpose is rejected. A new purpose later is a new value, not a format change.
