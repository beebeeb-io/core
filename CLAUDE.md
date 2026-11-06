# beebeeb core

This public Rust workspace is the cryptographic and protocol trust anchor for Beebeeb clients. The
workspace version is `0.2.2` and the license is AGPL-3.0-or-later.

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

- New file versions use chunk format v2. Readers retain only the compatibility paths documented in
  [docs/legacy-formats.md](docs/legacy-formats.md).
- A format, label, AAD, key derivation, or binding change is a coordinated migration. Never reinterpret
  existing bytes.
- File-content readers take the format and version commitment from authenticated metadata, never a
  server field. They finish authentication before publishing plaintext. The one exception is
  `beebeeb_transfer::range_session`: it releases only frames that `RangeOpener` authenticated at the
  requested index, for one recorded version, and only its `RangeOutcome::Whole` result means whole
  content. Its invariants I1 to I9 are in [docs/agent-notes.md](docs/agent-notes.md).
- New product operations use opaque handles and purpose-specific APIs. Raw binding exports are an
  explicit migration target behind the default-off `legacy-bindings` feature, not precedent.
- Native sign-in policy stays in `beebeeb-client`: password and any authenticator produce a locked
  session, then device approval or a passkey/recovery key plus email code supplies the account key,
  and key proof completes installation. Signup is web-only.
- Session storage has shared owner/key/API/generation state and one `session.token.{app_id}` per app.
  App sign-out removes one token; whole-device sign-out uses the service coordinator.
- Hostile sizes and counts use checked arithmetic and return errors. Secrets are wiped on drop and do
  not appear in errors or debug output.
- Generated bindings and vector JSON are generated, not hand-edited. Direct, range and backup vectors
  each have a drift guard that fails on hand edits.
- Backups: the root is the `backups_root` row, never a name or a path; a backup is written only by its
  device's own pass (the app and drive rules refuse every other create, write, rename and move under
  the root, and every change to a device's `.device.json`; the pass never goes through them); the pass
  never writes, moves, deletes, stages or hydrates a source file; a record at or under a key the walk
  did not look into (whatever its normal form or case) is never gone and never a move source; a pass
  marks a record only while it still names the remote id the pass read, and re-keys one only while it
  does or no record names that remote file (compare-and-set); only a complete remote listing marks
  anything removed elsewhere, and a removed file that changes comes back as a new file, never a
  version of the deleted one. Details are in [docs/agent-notes.md](docs/agent-notes.md).

All consumer boundaries, including the web exception and version-pin rule, are in
[docs/client-rules.md](docs/client-rules.md). Detailed format and key notes are in
[docs/agent-notes.md](docs/agent-notes.md).
