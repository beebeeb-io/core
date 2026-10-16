# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Chunk format v2 (task 1908): file-content frames now authenticate their position as AES-GCM
  associated data — `"beebeeb/chunk/v2" || len(file_id) || file_id || chunk_index || is_last`
  (STREAM construction). Previously (v1) frames carried no associated data, so a malicious
  server could reorder, duplicate, drop or truncate chunks within a file undetected. Same frame
  layout and sizes; the server is unaffected. `ChunkEncryptor` writes v2; `ChunkDecryptor` and
  every file-content decrypt path read v2 and v1, decide the format from what chunk 0
  authenticates under (never a server field) and lock it, reject out-of-order frames and frames
  after the last chunk, and fail at `finish()`/EOF when a v2 file ended early. A zero-frame body
  is now an error (it used to decrypt to an empty file).
- Breaking: `encrypt::decrypt_chunks_to_file`, `encrypt::decrypt_contiguous_to_file`,
  `beebeeb_upload::decrypt_downloaded_bytes` and the UniFFI `decrypt_chunks_to_file` /
  `decrypt_contiguous_to_file` take the file id. New: `ChunkDecryptor::{for_push_with_file_key,
  expect_format, format, chunks_decrypted, finish}`, `chunk_stream::{open_chunk, chunk_aad_v2,
  ChunkFormat, WRITE_FORMAT}`, WASM `WasmChunkDecryptor` + `decrypt_chunk_frame`, UniFFI
  `ChunkDecryptorHandle.{for_push_with_file_key, expect_format, chunk_format, finish}` and
  `FileKeyHandle.decrypt_chunk_frame`. Clients must move every file-content read to these before
  any client ships v2 writes.

### Added
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
- CI `Claims guard` job: runs the shared claims-guard engine plus
  `scripts/claims-guard/canon-sweep.sh`, the canon CLAIM_SWEEP over the whole tree
  (including any `design/` folder), so a false audit or compliance claim fails the build.

### Changed
- Nothing yet.

### Fixed
- Nothing yet.

### Removed
- `design/hifi/`: a stale snapshot of UI mockups committed with the initial import. Its mockup
  copy claimed that this code had been externally audited (naming a security firm and a date)
  and named the EU Digital Operational Resilience Act as a fit. Neither was ever true: `core`
  has **not** had an external audit (see "Audit status" in the README). The mockups live in
  the private design workspace; this repo is the crypto core.

### Security
- Nothing yet.

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
