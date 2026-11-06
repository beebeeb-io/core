# Building beebeeb core

`core` is a Rust 2024 workspace. The same crates compile natively (cli, server,
desktop), to WebAssembly (web), and to native mobile bindings (iOS, Android).

## Prerequisites

- Rust stable with edition 2024 support, plus Cargo.
- `wasm-pack` for the browser package.
- A UniFFI toolchain if you regenerate Swift or Kotlin bindings.
- For iOS artifacts: Xcode and the `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and
  `x86_64-apple-ios` Rust targets.
- For Android artifacts: an Android NDK, `cargo-ndk`, and the `aarch64-linux-android`,
  `armv7-linux-androideabi`, and `x86_64-linux-android` Rust targets.

## Workspace crates

| Crate | Purpose |
| --- | --- |
| `beebeeb-core` | Encryption, key derivation, recovery phrases, OPAQUE helpers, key exchange, the shared streaming chunk primitive, and sync protocol helpers. |
| `beebeeb-types` | Shared serializable types: cipher-suite identifiers, encrypted-blob shapes, KDF parameters, chunk metadata, storage constants. |
| `beebeeb-api` | I/O-free typed API descriptors, bounded answers, and account-flow types. |
| `beebeeb-client` | Native transport, sessions, and authentication, file, sync, transfer, sharing, local-data, backup, and platform services. |
| `beebeeb-store` | Native SQLite state, transfer queues, and cache metadata. |
| `beebeeb-transfer` | Transport-independent upload and download drivers. |
| `beebeeb-sync` | Legacy desktop sync prototype; do not use it for a new product. |
| `beebeeb-upload` | Legacy token-based upload client retained for compatibility. |
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

Install the Rust targets before building. The iOS script can install missing targets itself, but
doing it explicitly makes an offline or pinned-toolchain build predictable:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

```sh
./build-ios.sh        # writes BeebeebCore.xcframework/ and BeebeebCore.swift
./build-android.sh    # writes the Android .so + Kotlin bindings
```

The iOS script writes `BeebeebCore.xcframework/` and `BeebeebCore.swift` at the workspace root. The
Android script writes ABI libraries under `jniLibs/` and generated sources under `bindings/kotlin/`;
the consuming Xcode or Gradle project decides where to copy them.

Regenerating Swift/Kotlin bindings uses the `uniffi-bindgen` binary, which
requires the `cli` feature:

```sh
cargo run -p beebeeb-uniffi --features cli --bin uniffi-bindgen -- generate ...
```

`build-android.sh` already passes `--features cli` for the bindgen step.
`build-ios.sh` also enables `cli` for its host binding-generator step. Neither
script links `cli` into the shipping mobile library. Both scripts regenerate
bindings from the same feature surface they compile, before packaging the native
library.

The default binding surface intentionally excludes raw-key and token-based
compatibility calls. An old app that has not migrated can build and regenerate
the matching legacy surface explicitly:

```sh
BEEBEEB_LEGACY_BINDINGS=1 ./build-ios.sh
BEEBEEB_LEGACY_BINDINGS=1 ./build-android.sh
```

Do not enable `legacy-bindings` for a new app. After regeneration, grep the
generated header for the expected symbols before shipping.

`beebeeb-client` currently selects reqwest's `native-tls` transport. Apple
targets use Security.framework and are expected to cross-compile with Xcode.
Android's native-tls backend requires OpenSSL built for every selected ABI (and
the corresponding OpenSSL environment variables); `cargo-ndk` alone does not
supply it. If the Android build does not already provide those OpenSSL artifacts,
switching the client transport to rustls is the simpler portable option.

## Live client/server contract test

`beebeeb-client/tests/live_server.rs` is ignored during normal hermetic test runs. It provisions
isolated accounts and reads email codes from Mailpit, so use only a disposable local server with the
signup, recovery, device-link, public-share chunk, service, SSE, and short-session features enabled.

```sh
export BB_LIVE_API_URL=http://127.0.0.1:3000
export BB_LIVE_MAILPIT_URL=http://127.0.0.1:8025
cargo test -p beebeeb-client --test live_server --locked --offline -- \
  --ignored --test-threads=1
```

Do not run this suite against shared or production data. One session-expiry scenario is deliberately
manual; the client-side expiry transition also has a hermetic test.
