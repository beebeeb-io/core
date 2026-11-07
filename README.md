<p align="center">
  <a href="https://beebeeb.io"><img src="https://beebeeb.io/assets/beebeeb-icon.png" alt="beebeeb" width="72" height="72" /></a>
</p>
<h1 align="center">beebeeb core</h1>
<p align="center">Shared cryptography, protocol rules, storage, and bindings for Beebeeb clients.</p>

## Status

The workspace version is `0.3.0`. This is a breaking pre-1.0 release: consumers must read
[EXPORTS.md](EXPORTS.md), regenerate bindings where applicable, and update their core pin together.

Core protects file contents before upload. That does not make every client or protocol immune to a
malicious service: browser code can be replaced at delivery time, old formats have weaker integrity,
and some trust decisions are first-use. The current boundaries are documented in
[SECURITY.md](SECURITY.md).

## Workspace crates

| Crate | Purpose |
| --- | --- |
| `beebeeb-core` | Cryptography, key types, file formats, and pure protocol rules |
| `beebeeb-types` | Shared wire and domain types |
| `beebeeb-api` | I/O-free typed API requests, answers, and account flows |
| `beebeeb-client` | Native transport, sessions, and purpose-specific product services |
| `beebeeb-store` | Native SQLite account state, durable queues, and cache metadata |
| `beebeeb-transfer` | Transport-independent upload and download drivers |
| `beebeeb-wasm` | WebAssembly bindings |
| `beebeeb-uniffi` | Swift and Kotlin bindings |
| `beebeeb-upload` | Legacy upload client, retained for compatibility |
| `beebeeb-sync` | Legacy desktop sync prototype; not for product use |

Clients must follow [docs/client-rules.md](docs/client-rules.md). In particular, file content uses the
streaming APIs and authenticated metadata pins; the generic no-AAD helpers are not file-content APIs.
New file versions are written in chunk format v2. Compatibility readers are listed in
[docs/legacy-formats.md](docs/legacy-formats.md).

Native products start with `beebeeb-client` (or `NativeClientHandle` in Swift/Kotlin), not raw API or
key functions. Its services cover authentication and devices, files and sync, transfers and
thumbnails, sharing, contacts, search, settings, backup, File Provider, and ordered sign-out. A
password and any configured authenticator produce a locked session. A new device then uses either
device approval, a passkey plus an email code, or a recovery key plus an email code; installation
finishes with account-key proof. Account creation is web-only.

## Cryptography

Core uses established implementations of AES-256-GCM, HKDF-SHA256, Argon2id, X25519, BIP39, OPAQUE,
and SPAKE2. `MasterKey` and `FileKey` are non-`Clone` types that wipe their owned key material on drop.
Public functions generally return `Result`; this is not a claim that every process or dependency can
never panic.

## Build

The pinned Rust toolchain is in `rust-toolchain.toml`.

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings

wasm-pack build beebeeb-wasm --target web
./build-ios.sh
./build-android.sh
```

See [BUILDING.md](BUILDING.md) for binding and platform details, and
[CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change.

## Security

Report vulnerabilities to **security@beebeeb.io** as described in [SECURITY.md](SECURITY.md).
Core has not had an independent security review.

## License

[AGPL-3.0-or-later](LICENSE) — © Initlabs B.V., Wijchen, Netherlands.
