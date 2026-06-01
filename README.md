<p align="center">
  <a href="https://beebeeb.io"><img src="https://beebeeb.io/assets/beebeeb-icon.png" alt="beebeeb" width="72" height="72" /></a>
</p>
<h1 align="center">beebeeb core</h1>
<p align="center">The cryptography engine behind beebeeb. Files are sealed on your device — the server only ever sees ciphertext.</p>
<p align="center"><strong>We can't recover your data. Not even if we wanted to.</strong> That's the point.</p>
<p align="center">
  <a href="https://github.com/beebeeb-io/core/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/beebeeb-io/core/ci.yml?branch=main&label=CI" alt="CI" /></a> &nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-555.svg" alt="License: AGPL-3.0" /></a> &nbsp;
  <img src="https://img.shields.io/badge/rust-2024-555.svg" alt="Rust 2024" /> &nbsp;
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-555.svg" alt="Security policy" /></a>
</p>
<p align="center"><a href="https://beebeeb.io">Website</a> &nbsp;·&nbsp; <a href="https://beebeeb.io/security">How it works</a> &nbsp;·&nbsp; <a href="SECURITY.md">Report a vulnerability</a></p>
<p align="center"><sub>End-to-end encrypted cloud storage, built in Europe. Operated by Initlabs B.V., Wijchen, Netherlands.</sub></p>

---

## Why this exists

`core` is the one place beebeeb's cryptography lives. Every client depends on it, and none of them re-implement the crypto themselves: the web app consumes it as WebAssembly, the mobile apps through UniFFI bindings, and the CLI, server, and desktop sync engine as a native Rust git dependency. Writing key derivation and chunk encryption once — in audited Rust — means a fix or a hardening lands in every client at once, and there's no second implementation to drift, disagree, or get a corner wrong.

## Usage

The flow is the same everywhere: derive a `MasterKey` from the user's password, derive a per-file `FileKey` from it, then encrypt or decrypt chunks under that file key. Raw key bytes never leave the device.

```rust
use beebeeb_core::kdf::{derive_master_key, derive_file_key};
use beebeeb_core::encrypt::{encrypt_chunk, decrypt_chunk};

// 1. Master key from the password (Argon2id). `salt` is per-user, >= 16 bytes.
let master = derive_master_key(password, salt)?;

// 2. Per-file key from the master key (HKDF-SHA256), scoped to one file_id.
let file_key = derive_file_key(&master, file_id);

// 3. Seal a chunk (AES-256-GCM, fresh random nonce) and open it again.
let sealed = encrypt_chunk(&file_key, plaintext)?;   // -> EncryptedBlob
let opened = decrypt_chunk(&file_key, &sealed)?;      // -> Vec<u8>
assert_eq!(opened, plaintext);
```

For streaming whole files chunk-by-chunk (one shared encrypt loop across every client, peak memory ≈ one chunk) see `chunk_stream::ChunkEncryptor` / `ChunkDecryptor`.

## Consumed by

| Client | How it links `core` |
| --- | --- |
| web | WebAssembly — the `beebeeb-wasm` crate, built with `wasm-pack` |
| mobile | UniFFI — Swift + Kotlin bindings from `beebeeb-uniffi` |
| cli | native Rust git dependency |
| server | native Rust git dependency (shared types + protocol helpers) |
| desktop | native Rust git dependency (`beebeeb-sync` sync engine) |

## Cryptographic primitives

| Primitive | Use |
| --- | --- |
| AES-256-GCM | File, chunk, metadata, and local wrapping encryption. |
| X25519 | Key exchange for sharing and client-side key agreement. |
| Argon2id | Password-based key derivation. |
| HKDF-SHA256 | Per-file key derivation from the master key and file identifiers. |
| BIP39 | Recovery phrase generation and recovery. |
| OPAQUE | Password-authenticated key exchange where the server never learns the password. |

## Build

```sh
cargo test --workspace          # full test suite
cargo build --workspace --release

wasm-pack build beebeeb-wasm --target web   # web (WASM) package -> beebeeb-wasm/pkg
./build-ios.sh                              # iOS xcframework + Swift bindings
./build-android.sh                          # Android .so + Kotlin bindings
```

Deeper build, binding-regeneration, and environment detail lives in [BUILDING.md](BUILDING.md).

## Security invariants

- `MasterKey` and `FileKey` are 32 bytes, **not** `Clone`, and zeroized on drop — no accidental key copies in memory.
- Every file gets its own key via `HKDF(master_key, file_id)` — one compromised file key can't open another.
- The recovery phrase **is** the master secret; the password wraps access to it, it doesn't replace it.
- Crypto paths return `Result` and never panic.
- Don't reimplement any of this per-client. If a client needs a crypto operation, it goes here.

## Security

Found a vulnerability? Email **security@beebeeb.io** — see [SECURITY.md](SECURITY.md).

## Part of beebeeb

End-to-end encrypted, zero-knowledge cloud storage — made in Europe.
[core](https://github.com/beebeeb-io/core) · [cli](https://github.com/beebeeb-io/cli) · [web](https://github.com/beebeeb-io/web) · [mobile](https://github.com/beebeeb-io/mobile) · [desktop](https://github.com/beebeeb-io/desktop) · [website](https://beebeeb.io)

## License

[AGPL-3.0-or-later](LICENSE) — © Initlabs B.V. (KvK 95157565), Wijchen, Netherlands.
