# beebeeb-io/core

Cryptographic core, shared types, and sync engine. This is the trust anchor — every client depends on this.

## Crates

- `beebeeb-core` — AES-256-GCM encryption, Argon2id KDF (256MiB/4iter/2par), BIP39 recovery phrases, HKDF per-file key derivation
- `beebeeb-types` — CipherSuite, EncryptedBlob, KdfParams, ChunkMeta (shared across all repos)
- `beebeeb-sync` — Desktop sync engine: file watcher (notify), conflict resolution (KeepBoth default), selective sync

## Build & test

```sh
cargo test --workspace    # 53 tests (core: 26, sync: 27)
cargo clippy --workspace -- -D warnings
cargo fmt -- --check
```

## Key types

- `MasterKey` — 32 bytes, NOT Clone, zeroized on drop. Created from password (Argon2id) or recovery phrase.
- `FileKey` — 32 bytes, per-file via HKDF. `derive_file_key(master_key, file_id)`.
- `EncryptedBlob` — cipher_suite + nonce (Vec<u8>) + ciphertext (Vec<u8>).
- `encrypt_chunk(key: &FileKey, plaintext)` / `decrypt_chunk(key: &FileKey, blob)` — AES-256-GCM.

## Security invariants

- MasterKey and FileKey are NOT Clone — prevents accidental key copies in memory
- All intermediate key buffers use `Zeroizing<[u8; 32]>` — zeroed on drop
- Each file gets its own key via HKDF(master_key, file_id) — limits blast radius
- Recovery phrase IS the master secret — password wraps it, doesn't replace it
- No panics in crypto paths — everything returns Result

## Design references

Design files are in the workspace root: `../../design/hifi/`

## License

AGPL-3.0-or-later


## Keep shared docs in sync

When you add/change/remove endpoints, types, build commands, or dependencies: update the relevant skill file in `/home/guus/code/beebeeb.io/.claude/skills/` (beebeeb-api.md, beebeeb-designs.md, beebeeb-stack.md, beebeeb-dev.md). Other agents depend on these being accurate.
