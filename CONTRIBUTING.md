# Contributing to Beebeeb Core

Thank you for contributing. This workspace is security-sensitive and changes can affect every client.

## Setup

Install Git, Python 3, ripgrep, and the Rust toolchain pinned by `rust-toolchain.toml`. The independent
vector checks also need Python's `cryptography` package; the documentation guards run `rg`.

```sh
git clone https://github.com/beebeeb-io/core.git
cd core
python3 -m pip install cryptography argon2-cffi
cargo test --workspace --locked
```

Do not hand-edit generated bindings or generated vector JSON. Change its source and regenerate it.

## Checks

Run these before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash scripts/check-test-vectors.sh
bash scripts/check-no-legacy-writes.sh
bash scripts/check-doc-symbols.sh
bash scripts/check-core-pins-documented.sh
```

CI additionally checks the WASM JavaScript surface, dependency advisories, dependency licenses and
sources, and public added-line policy. Those dependency tools are installed by CI; contributors do not
need to install them globally.

## Security and compatibility changes

Discuss changes to primitives, labels, AAD, key derivation, stored formats, wire formats, or binding
exports before implementing them. A changed existing label is a migration, not a refactor. Add hostile
input tests and independent known-answer vectors where appropriate.

Compatibility readers are inventoried in [docs/legacy-formats.md](docs/legacy-formats.md); new code must
not write those formats. Consumer responsibilities are in [docs/client-rules.md](docs/client-rules.md).

## Pull requests

Keep changes focused, explain compatibility effects, add tests, and report which checks ran. Security
issues must go to **security@beebeeb.io**, not a public issue.

By contributing, you confirm you have the right to submit the work under
[AGPL-3.0-or-later](LICENSE). No separate contributor license agreement is required.
