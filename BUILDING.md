# Building beebeeb core

`core` is a Rust 2024 workspace. The same crates compile natively (cli, server,
desktop), to WebAssembly (web), and to native mobile bindings (iOS, Android).

## Prerequisites

- Rust stable with edition 2024 support, plus Cargo.
- `wasm-pack` for the browser package.
- A UniFFI toolchain if you regenerate Swift or Kotlin bindings.
- For mobile artifacts: the relevant Rust targets installed (`rustup target add ...`).

## Workspace crates

| Crate | Purpose |
| --- | --- |
| `beebeeb-core` | Encryption, key derivation, recovery phrases, OPAQUE helpers, key exchange, the shared streaming chunk primitive, and sync protocol helpers. |
| `beebeeb-types` | Shared serializable types: cipher-suite identifiers, encrypted-blob shapes, KDF parameters, chunk metadata, storage constants. |
| `beebeeb-sync` | Desktop sync engine primitives: file watching, conflict handling, selective sync, sync state. |
| `beebeeb-upload` | Upload pipeline helpers shared across clients. |
| `beebeeb-wasm` | WebAssembly bindings consumed by the web client (`beebeeb-wasm/pkg`). |
| `beebeeb-uniffi` | UniFFI library and binding generator for Swift and Kotlin. |

## Native build, test, and checks

```sh
cargo build --workspace --release
cargo test  --workspace
cargo check --workspace
cargo clippy --workspace -- -D warnings
cargo fmt -- --check
```

`core` is a library workspace and needs no runtime environment variables.
Consumers (web, cli, mobile, server) own their own runtime configuration.

## WebAssembly (web client)

```sh
wasm-pack build beebeeb-wasm --target web
```

The generated npm package is written to `beebeeb-wasm/pkg`. `beebeeb-core` is
target-gated so it builds for `wasm32-unknown-unknown`: `rusqlite` (used only by
the native FileProvider cache) is excluded on wasm, and `fp_cache` is
`#[cfg(not(target_arch = "wasm32"))]`. Native builds are unaffected.

## Mobile bindings (iOS, Android)

```sh
./build-ios.sh        # writes BeebeebCore.xcframework/ and BeebeebCore.swift
./build-android.sh    # writes the Android .so + Kotlin bindings
```

The iOS artifacts are copied into `repos/mobile/ios/` and committed; the Xcode
project links the `.a` slices from there. The size-optimized release profile
(`opt-level = "z"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`)
plus the `cli`-feature gate on `beebeeb-uniffi` keeps the device staticlib
around 22 MB.

Regenerating Swift/Kotlin bindings uses the `uniffi-bindgen` binary, which
requires the `cli` feature:

```sh
cargo run -p beebeeb-uniffi --features cli --bin uniffi-bindgen -- generate ...
```

`build-android.sh` already passes `--features cli` for the bindgen step.
`build-ios.sh` does not need it — the Swift bindings are pre-generated and copied
from `beebeeb-uniffi/bindings/`. After regenerating, grep the regenerated header
for the new symbols before shipping.
