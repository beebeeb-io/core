# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet.

### Changed
- Nothing yet.

### Fixed
- Nothing yet.

### Removed
- Nothing yet.

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
