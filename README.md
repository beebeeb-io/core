<p align="center">
  <img src="https://beebeeb.io/icon.png" alt="Beebeeb" width="60" />
</p>
<h3 align="center">Beebeeb Core</h3>
<p align="center">Cryptographic core, shared types, and sync engine for Beebeeb — zero-knowledge end-to-end encryption.</p>

<p align="center">
  <a href="https://github.com/beebeeb-io/core/blob/main/LICENSE"><img src="https://img.shields.io/github/license/beebeeb-io/core" alt="License"></a>
  <a href="https://github.com/beebeeb-io/core/actions"><img src="https://img.shields.io/github/actions/workflow/status/beebeeb-io/core/ci.yml" alt="CI"></a>
  <a href="https://github.com/beebeeb-io/core/graphs/contributors"><img src="https://img.shields.io/github/contributors/beebeeb-io/core" alt="Contributors"></a>
  <a href="https://github.com/beebeeb-io/core/stargazers"><img src="https://img.shields.io/github/stars/beebeeb-io/core" alt="Stars"></a>
  <a href="https://github.com/beebeeb-io/core/issues"><img src="https://img.shields.io/github/issues/beebeeb-io/core" alt="Issues"></a>
</p>

---

## What is Beebeeb?

Beebeeb is end-to-end encrypted cloud storage where your files are encrypted before they leave your device. The server never sees your plaintext data, file names, or encryption keys. Beebeeb is open source and built by [Initlabs B.V.](https://beebeeb.io), Wijchen, Netherlands.

## This repo

This is the **trust anchor** of the Beebeeb ecosystem. Every client -- CLI, desktop, web, and mobile -- depends on these crates for encryption, key derivation, type definitions, and file sync. The code is written in Rust and compiles to native binaries, WebAssembly, and mobile FFI bindings from a single source.

### Crates

| Crate | Description |
|---|---|
| [`beebeeb-core`](./beebeeb-core) | AES-256-GCM encryption, Argon2id key derivation, BIP39 recovery phrases, HKDF per-file key derivation |
| [`beebeeb-types`](./beebeeb-types) | Shared types (`CipherSuite`, `EncryptedBlob`, `KdfParams`, `ChunkMeta`) used across all repos |
| [`beebeeb-sync`](./beebeeb-sync) | Desktop sync engine: file watcher, conflict resolution, selective sync |
| [`beebeeb-wasm`](./beebeeb-wasm) | WebAssembly bindings for use in browsers via `wasm-bindgen` |

## Tech stack

| Layer | Technology |
|---|---|
| Language | Rust (Edition 2024) |
| Symmetric encryption | AES-256-GCM |
| Key derivation | Argon2id (256 MiB memory, 4 iterations, 2 parallelism) |
| Per-file keys | HKDF-SHA256 |
| Recovery phrases | BIP39 (24 words) |
| Key exchange | X25519 |
| Key hygiene | `zeroize` -- all key material zeroed on drop |
| WASM target | `wasm-bindgen` + `wasm-pack` |
| File watching | `notify` crate (debounced, 100 ms) |

## Architecture

**One Rust crate, compiled everywhere.** The cryptographic core is written once and shipped to every platform:

- **Web** -- compiled to WebAssembly via `wasm-pack`, consumed by the browser client
- **Desktop** -- native Rust binary using `beebeeb-sync` for background file sync
- **CLI** -- linked directly as a Cargo dependency
- **Mobile** (planned) -- UniFFI bindings for Swift and Kotlin

This means every client uses the exact same encryption logic. There is no room for platform-specific reimplementation bugs.

### Key types

- `MasterKey` -- 32 bytes, **not** `Clone`, zeroized on drop. Created from a password (Argon2id) or a recovery phrase.
- `FileKey` -- 32 bytes, derived per file via `HKDF(master_key, file_id)`. Limits blast radius if a single key is compromised.
- `EncryptedBlob` -- cipher suite identifier + nonce + ciphertext. Self-describing and forward-compatible.

## Getting started

### Prerequisites

- [Rust](https://rustup.rs/) (stable, edition 2024)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (only for WASM builds)

### Build and test

```sh
# Clone the repo
git clone https://github.com/beebeeb-io/core.git
cd core

# Run the full test suite
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt -- --check
```

### Build WASM bindings

```sh
wasm-pack build beebeeb-wasm --target web
```

## Security

Beebeeb is designed around zero-knowledge encryption. The server never has access to your plaintext data or keys.

**Security invariants enforced in this crate:**

- `MasterKey` and `FileKey` do not implement `Clone` -- this prevents accidental key copies in memory
- All intermediate key buffers use `Zeroizing<[u8; 32]>` and are zeroed on drop
- Each file gets its own key via HKDF -- compromising one file key does not affect others
- The recovery phrase is the master secret; a password wraps it but does not replace it
- No panics in cryptographic code paths -- everything returns `Result`

**Found a vulnerability?** Please report it responsibly. See [SECURITY.md](./SECURITY.md) for details, or email [security@beebeeb.io](mailto:security@beebeeb.io). We aim to acknowledge reports within 48 hours.

## Contributing

We welcome contributions! Whether it is a bug report, a feature request, or a pull request -- we appreciate your help making Beebeeb better.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Make your changes and add tests
4. Run the test suite (`cargo test --workspace`) and linter (`cargo clippy --workspace -- -D warnings`)
5. Commit your changes -- pre-commit hooks will run secret scanning automatically
6. Open a pull request against `main`

Please make sure all tests pass and clippy reports no warnings before submitting.

## Built with Beebeeb

This crate is part of the Beebeeb ecosystem:

| Repo | Description |
|---|---|
| **[core](https://github.com/beebeeb-io/core)** | Cryptographic core, shared types, and sync engine (you are here) |
| [cli](https://github.com/beebeeb-io/cli) | `bb` -- end-to-end encrypted cloud storage from the terminal |
| [desktop](https://github.com/beebeeb-io/desktop) | Desktop sync client for macOS, Windows, and Linux |

## License

This project is licensed under the [GNU Affero General Public License v3.0 or later](./LICENSE).

Copyright (c) Initlabs B.V.

## Links

- [Website](https://beebeeb.io)
- [Security policy](./SECURITY.md)
- [GitHub organization](https://github.com/beebeeb-io)
