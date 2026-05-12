# Contributing to Beebeeb Core

Thanks for your interest in contributing to the Beebeeb cryptography and sync library.

## Prerequisites

- Rust 1.85+ (stable toolchain)
- Git

## Development setup

```sh
git clone https://github.com/beebeeb-io/core.git
cd core
cargo test --workspace
```

All 53 tests across `beebeeb-core` and `beebeeb-sync` should pass.

## Code quality checks

Run these before submitting a pull request:

```sh
cargo fmt -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Crypto changes

This is a cryptography library. Changes to primitives, key derivation, or encryption flows require extra scrutiny and will go through an extended review cycle. Please open an issue to discuss the change before submitting a PR.

## Pull request process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, ensuring all checks above pass.
3. Write or update tests for your changes.
4. Open a pull request with a clear description of what and why.

## Security

If you discover a security vulnerability, **do not open a public issue**. Email [security@beebeeb.io](mailto:security@beebeeb.io) instead. See [SECURITY.md](SECURITY.md) for details.

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0-or-later](LICENSE).
