# Local recovery snapshot and per-session scratch seal (design note)

Status: design for review, no code yet. Module: `beebeeb_core::local_seal` (new, `beebeeb-core/src/local_seal.rs`).
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
same pattern as `derive_file_key` (an internal `derive_snapshot_key`). The key is 32 bytes, `FileKey`-typed,
`Zeroizing`, never exported. `file_id` is the canonical item id text (UTF-8); a non-canonical id is `InvalidInput`
(`item_class` decides), never treated as a different file. The master key is the account key that exists only while
unlocked, so a locked or signed-out app cannot open a snapshot.

New labels, each to be added to `LABELS` in `label_table_tests.rs` (the completeness test fails otherwise):

| name | bytes | slot | with |
|---|---|---|---|
| `SNAPSHOT_KEY_LABEL` | `beebeeb-local-snapshot-v1` | InfoWithId | master key (id appended) |
| `SNAPSHOT_AAD_LABEL` | `beebeeb-local-snapshot-aad-v1` | Aad | the snapshot key |
| `SCRATCH_KEY_LABEL` | `beebeeb-scratch-chunk-key-v1` | Info | the session scratch key |
| `SCRATCH_AAD_LABEL` | `beebeeb-scratch-chunk-aad-v1` | Aad | the scratch chunk key |

No label is a prefix of another HKDF `info` label; no entry is needed in `CROSS_SLOT_PREFIX_PAIRS` (the test
confirms). A future incompatible change uses `v2` labels and a new format byte, never a reinterpretation.

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
handshake). `MAX_SNAPSHOT_BYTES` is 256 MiB (equal to `MAX_CHUNK_SIZE`; the app's own cap `MAX_SAVE_BYTES` is smaller).
Larger input is `InvalidInput`. AES-GCM's per-message limit is not close.

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

The header carries `kind`, `base_version` and `saved_at` in clear (they are not secret: no name, no content, and the
app shows "unsaved changes from 14:32" before unlocking nothing) and the AAD repeats them, so editing the header fails
the tag. The file id is NOT stored in the blob: the caller supplies it (it names the blob's file and directory), so a
blob moved to another file's slot does not open. `open` returns the meta it authenticated. The magic and version are
checked first; an unknown `header_version` is an error, never a fallback.

### 1.5 Atomic replace (engine, not core)

Core is I/O-free for this module: it returns and takes bytes. The engine writes one blob per open document in a
per-account folder under the app's data folder: write `<id>.bbsnap.tmp` in the same folder (0600 on Unix), fsync the
file, `rename` over `<id>.bbsnap`, fsync the folder. The previous blob is replaced only by that rename, so a crash
leaves the old or the new one, never half. A leftover `.tmp` is deleted at startup, never opened. The engine opens a
new blob (or at least the header) after writing it before it drops the previous snapshot of the editor's memory.

### 1.6 What sign-out wipes

Delete (best effort, then verify absent) every `.bbsnap` and `.bbsnap.tmp` of the signing-out account, on save,
discard and sign-out, as contract section 5.4 says. No key is ever stored, so a lock or a leftover blob after a crash
of the wipe is unreadable without the master key. The engine must delete only its own account's folder; a blob of
another account on the same PC is never opened (wrong key gives `CoreError::Decryption`) and never deleted by this
account's sign-out.

## 2. Scratch seal

A random key per app session, in memory only, for (a) a large document the host spills out of memory and (b) the
staged save payload before upload. A restart makes every old scratch file unreadable by design; the engine deletes
leftovers at start (no recovery from scratch: that is what the snapshot is for).

### 2.1 Key

`ScratchKey::generate() -> Result<ScratchKey, CoreError>`: 32 bytes from the OS CSPRNG (the same source as
`FileKey::generate`), never derived from the master key or any account key. It is not `Clone`, `Debug` prints
`ScratchKey(..)`, there is no `as_bytes`, `to_bytes`, `Serialize` or `From<[u8; 32]>` in a shipped build (a
`cfg(test)` / `test-support` constructor exists for vectors only, like `with_vector_nonces`). It is zeroized on drop.
The sealing key is `derive_file_subkey(scratch_key, SCRATCH_KEY_LABEL)`, so the raw random key never seals directly.

### 2.2 Stream format

A scratch file is a header plus fixed-size frames. `ScratchWriter` takes a fresh random 16-byte `scratch_id` (the
per-file id), a `purpose: u8` (1 spill, 2 staged save) and a chunk size (default 1 MiB, `1..=MAX_CHUNK_SIZE`).

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
An empty document is one final frame of zero plaintext bytes. The index is a `u32`; passing `u32::MAX` frames is an
error (checked arithmetic). A file is also bounded by `MAX_SCRATCH_BYTES` (4 GiB, open question).

### 2.3 Reader contract

`ScratchReader<R: Read>` implements `Read` and decrypts one frame at a time, reading ahead one byte to learn whether
a frame is the last. It follows the same rule as the chunk readers in core: plaintext of a frame is released only
after that frame authenticated, but whole-file integrity (truncation, trailing bytes) is known only at EOF, so a
consumer that publishes the payload MUST NOT use any of it until a full read ended in `Ok`, and discards all of it on
any `Err`. For the staged save the engine therefore runs `verify_scratch` first (one full authenticating pass that
returns the plaintext length and keeps nothing) and only then starts the upload pass.

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
pub fn peek_snapshot_meta(sealed: &[u8]) -> Result<SnapshotMeta, CoreError>;

pub struct ScratchKey { /* private */ }
impl ScratchKey { pub fn generate() -> Result<Self, CoreError>; }

pub const DEFAULT_SCRATCH_CHUNK: u32 = 1024 * 1024;
pub struct ScratchWriter<W: Write> { /* private */ }
impl<W: Write> ScratchWriter<W> {
    pub fn new(key: &ScratchKey, out: W, purpose: u8, chunk_size: u32) -> Result<Self, CoreError>;
    pub fn scratch_id(&self) -> [u8; 16];
    pub fn finish(self) -> Result<(W, u64 /* plaintext bytes */), CoreError>; // seals the final frame
}                                                  // impl Write: buffers, seals full non-final chunks
pub struct ScratchReader<R: Read> { /* private */ }
impl<R: Read> ScratchReader<R> {
    pub fn new(key: &ScratchKey, input: R, expected_purpose: u8) -> Result<Self, CoreError>;
    pub fn scratch_id(&self) -> [u8; 16];
}                                                  // impl Read
pub fn verify_scratch<R: Read>(key: &ScratchKey, input: R, expected_purpose: u8) -> Result<u64, CoreError>;
```

Errors: `CoreError::Decryption` for any tag failure, wrong key, truncation, reorder or trailing data (one error, no
oracle on which); `InvalidInput` for a bad header, size, id, kind or purpose; `Io` for the sink or source (inside
`Read`/`Write` it surfaces as `io::Error` wrapping the same). A dropped `ScratchWriter` without `finish` leaves a file
that fails to open (it has no final frame), by design. The plaintext returned by `open_recovery_snapshot` is `Zeroizing`.

Not exported to uniffi or wasm: every item above, `ScratchKey` in particular (no key bytes may cross an FFI
boundary), and `scripts/check-doc-symbols.sh` / the binding crates get no entry. A test greps `beebeeb-uniffi` and
`beebeeb-wasm` sources for `local_seal` and fails if one appears.

## 4. Test-vector plan

New `test-vectors/local_seal.json`, checked by `scripts/check-test-vectors.sh` and a `local_seal` unit module:

- Snapshot: fixed master key, file id, meta and nonce (a `cfg(test)` / `test-support` seam like
  `ChunkEncryptor::with_vector_nonces`): derived key hex, AAD hex, header hex, full sealed blob hex, for an empty, a
  one-byte and a 100-byte plaintext. Open must return the same bytes.
- Scratch: a fixed key and nonces (same seam), chunk size 16: header, per-frame AAD and the file for 0, 15, 16, 17
  and 48 bytes (the empty, short-final, exact-multiple and multi-frame edges).
- Negative cases, each must fail with `Decryption` and release no final plaintext: flip each header byte, flip one
  ciphertext bit, wrong master key, wrong file id, wrong `base_version`/`saved_at`/`kind`, wrong magic and version
  (`InvalidInput`); scratch: drop the last frame, drop a middle frame, swap two frames, duplicate a frame, append a
  frame after the final one, splice a frame from a second scratch file, wrong key, wrong purpose, chunk-size field
  edited; chunk size `0` and above `MAX_CHUNK_SIZE`; oversize input.
- `label_table_tests.rs` lists the four labels (section 1.2); a test that the snapshot key differs from
  `derive_file_key` for the same id, and that a snapshot blob does not open under the file key.
- Nonce freshness: two seals of the same input differ (as `shipped_name_writers_draw_a_fresh_nonce_each_call` does).

## 5. Threat model

| Threat | Result |
|---|---|
| Stolen disk or backup of the data folder | Snapshots are AES-256-GCM under a key from the master key, which is not on disk; scratch files are under a key that died with the process. Header leaks kind, base version, saved-at and approximate size (accepted, listed). No plaintext file exists. |
| Another account on the same PC | A different master key gives a different snapshot key: `Decryption`. The folder is per account and sign-out deletes only its own. Scratch is per process and 0600; another account's process has another random key. |
| Truncation | Snapshot: one frame, a cut blob fails the tag. Scratch: the final flag is bound, so a cut file fails at the last present frame; trailing data after the final frame fails. |
| Reorder, duplicate or splice of frames | Index and `scratch_id` are in every frame's AAD: fail. |
| Replace a blob with another file's blob | `file_id` is in the AAD and not in the blob: fail. |
| Replay of an older snapshot of the same file | Not detectable by core (a valid old blob is valid). The engine keeps one blob per file, replaced atomically, shows `saved_at` in the restore prompt ("changes from 14:32"), and the user chooses Restore or Discard; the worst outcome is losing recent unsaved edits, never a silent overwrite of a saved version. Accepted, noted. |
| A snapshot uploaded or opened as file content | The key and AAD are purpose-bound; it never opens as a v2 frame and no v2 frame opens as a snapshot. |
| Nonce reuse | Random 96-bit nonces; per-key volume is far below 2^32 (section 1.3). Scratch: fresh random key per session. |
| Memory remnants | Keys and returned plaintext are `Zeroizing`; the key types are not `Clone` and never in `Debug` or errors. |

## 6. Open questions

1. Q3: dedicated local label (recommended here) or the upload format (contract recommendation)? Guus decides; this
   note assumes the first.
2. Should core provide the atomic file replace helper (section 1.5) so the rules exist once, or stay in the engine?
   Recommended: engine, with a test that kills between steps.
3. `MAX_SNAPSHOT_BYTES` 256 MiB and `MAX_SCRATCH_BYTES` 4 GiB: confirm against the app's `MAX_SAVE_BYTES`.
4. Is `saved_at` in clear acceptable? (It leaks when the user last edited a document, not what.)
5. Spill and staged save in one `purpose` space (1 and 2) are enough, or does the engine want a third (a clipboard
   image)? Adding one later is a value, not a format change.
