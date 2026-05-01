# Graph Report - core  (2026-05-01)

## Corpus Check
- 72 files · ~110,307 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1042 nodes · 1787 edges · 19 communities detected
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 263 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]

## God Nodes (most connected - your core abstractions)
1. `UniffiLib` - 70 edges
2. `ok` - 40 edges
3. `derive_master_key()` - 27 edges
4. `derive_file_key()` - 27 edges
5. `rustCallWithError()` - 19 edges
6. `IntegrityCheckingUniffiLib` - 19 edges
7. `encrypt_chunk()` - 19 edges
8. `decrypt_chunk()` - 18 edges
9. `takeFromExternrefTable0()` - 18 edges
10. `takeFromExternrefTable0()` - 18 edges

## Surprising Connections (you probably didn't know these)
- `generate_recovery_phrase()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/recovery.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `derive_key_from_entropy()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/recovery.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `client_registration_start()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/opaque_protocol.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `server_registration_start()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/opaque_protocol.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `client_registration_finish()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/opaque_protocol.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (58): ByReference, ByValue, CryptoException, Decryption, Disposable, EncryptedData, FfiConverterByteArray, FfiConverterRustBuffer (+50 more)

### Community 1 - "Community 1"
Cohesion: 0.04
Nodes (84): computeRecoveryCheck(), createReader(), createWriter(), CryptoError, Decryption, Encryption, InvalidInput, InvalidRecoveryPhrase (+76 more)

### Community 2 - "Community 2"
Cohesion: 0.09
Nodes (74): hex(), main(), ok, compute_recovery_check(), compute_recovery_check_works(), CryptoError, decrypt_chunk(), decrypt_metadata() (+66 more)

### Community 3 - "Community 3"
Cohesion: 0.03
Nodes (1): UniffiLib

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (39): FfiConverterTypeCryptoError, Conflict, conflict_without_prior_sync_when_timestamps_differ(), ConflictResolution, detect_conflicts(), detects_conflict_when_both_sides_changed(), FileMeta, loser_filename() (+31 more)

### Community 5 - "Community 5"
Cohesion: 0.07
Nodes (45): addToExternrefTable0(), compute_recovery_check(), debugString(), decodeText(), decrypt_chunk(), decrypt_metadata(), derive_file_key(), derive_master_key() (+37 more)

### Community 6 - "Community 6"
Cohesion: 0.12
Nodes (27): Opaque, config_new_sets_defaults(), config_roundtrips_through_json(), SyncConfig, SyncMode, BeebeebCs, client_login_finish(), client_login_start() (+19 more)

### Community 7 - "Community 7"
Cohesion: 0.16
Nodes (34): addToExternrefTable0(), compute_recovery_check(), debugString(), decodeText(), decrypt_chunk(), decrypt_metadata(), derive_file_key(), derive_master_key() (+26 more)

### Community 8 - "Community 8"
Cohesion: 0.12
Nodes (25): InvalidInput, Kdf, derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), different_file_ids_yield_different_keys() (+17 more)

### Community 9 - "Community 9"
Cohesion: 0.11
Nodes (1): IntegrityCheckingUniffiLib

### Community 10 - "Community 10"
Cohesion: 0.23
Nodes (13): compute_recovery_check(), derive_share_key(), derive_x25519_private(), derive_x25519_public(), envelope_round_trip(), OpaqueEnvelope, recovery_check_deterministic(), share_key_derivation() (+5 more)

### Community 11 - "Community 11"
Cohesion: 0.31
Nodes (16): Encryption, decrypt_chunk(), decrypt_metadata(), empty_plaintext_roundtrip(), encrypt_chunk(), encrypt_metadata(), invalid_nonce_length_fails(), large_plaintext_roundtrip() (+8 more)

### Community 16 - "Community 16"
Cohesion: 0.18
Nodes (11): UniffiInternalError, bufferOverflow, incompleteData, rustPanic, unexpectedEnumCase, unexpectedNullPointer, unexpectedOptionalTag, unexpectedRustCallError (+3 more)

### Community 30 - "Community 30"
Cohesion: 0.43
Nodes (2): NSLock, UniffiHandleMap

### Community 31 - "Community 31"
Cohesion: 0.25
Nodes (1): FfiConverter

### Community 44 - "Community 44"
Cohesion: 0.4
Nodes (3): CipherSuite, KdfAlgorithm, KdfParams

### Community 56 - "Community 56"
Cohesion: 0.67
Nodes (2): ChunkMeta, EncryptedBlob

### Community 59 - "Community 59"
Cohesion: 1.0
Nodes (1): CoreError

### Community 60 - "Community 60"
Cohesion: 1.0
Nodes (1): SyncError

## Knowledge Gaps
- **56 isolated node(s):** `EncryptedBlob`, `ChunkMeta`, `CipherSuite`, `KdfAlgorithm`, `bufferOverflow` (+51 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 3`** (70 nodes): `UniffiLib`, `.ffi_beebeeb_uniffi_rust_future_cancel_f32()`, `.ffi_beebeeb_uniffi_rust_future_cancel_f64()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i16()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i32()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i64()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i8()`, `.ffi_beebeeb_uniffi_rust_future_cancel_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u16()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u32()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u64()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u8()`, `.ffi_beebeeb_uniffi_rust_future_cancel_void()`, `.ffi_beebeeb_uniffi_rust_future_complete_f32()`, `.ffi_beebeeb_uniffi_rust_future_complete_f64()`, `.ffi_beebeeb_uniffi_rust_future_complete_i16()`, `.ffi_beebeeb_uniffi_rust_future_complete_i32()`, `.ffi_beebeeb_uniffi_rust_future_complete_i64()`, `.ffi_beebeeb_uniffi_rust_future_complete_i8()`, `.ffi_beebeeb_uniffi_rust_future_complete_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_complete_u16()`, `.ffi_beebeeb_uniffi_rust_future_complete_u32()`, `.ffi_beebeeb_uniffi_rust_future_complete_u64()`, `.ffi_beebeeb_uniffi_rust_future_complete_u8()`, `.ffi_beebeeb_uniffi_rust_future_complete_void()`, `.ffi_beebeeb_uniffi_rust_future_free_f32()`, `.ffi_beebeeb_uniffi_rust_future_free_f64()`, `.ffi_beebeeb_uniffi_rust_future_free_i16()`, `.ffi_beebeeb_uniffi_rust_future_free_i32()`, `.ffi_beebeeb_uniffi_rust_future_free_i64()`, `.ffi_beebeeb_uniffi_rust_future_free_i8()`, `.ffi_beebeeb_uniffi_rust_future_free_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_free_u16()`, `.ffi_beebeeb_uniffi_rust_future_free_u32()`, `.ffi_beebeeb_uniffi_rust_future_free_u64()`, `.ffi_beebeeb_uniffi_rust_future_free_u8()`, `.ffi_beebeeb_uniffi_rust_future_free_void()`, `.ffi_beebeeb_uniffi_rust_future_poll_f32()`, `.ffi_beebeeb_uniffi_rust_future_poll_f64()`, `.ffi_beebeeb_uniffi_rust_future_poll_i16()`, `.ffi_beebeeb_uniffi_rust_future_poll_i32()`, `.ffi_beebeeb_uniffi_rust_future_poll_i64()`, `.ffi_beebeeb_uniffi_rust_future_poll_i8()`, `.ffi_beebeeb_uniffi_rust_future_poll_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_poll_u16()`, `.ffi_beebeeb_uniffi_rust_future_poll_u32()`, `.ffi_beebeeb_uniffi_rust_future_poll_u64()`, `.ffi_beebeeb_uniffi_rust_future_poll_u8()`, `.ffi_beebeeb_uniffi_rust_future_poll_void()`, `.ffi_beebeeb_uniffi_rustbuffer_alloc()`, `.ffi_beebeeb_uniffi_rustbuffer_free()`, `.ffi_beebeeb_uniffi_rustbuffer_from_bytes()`, `.ffi_beebeeb_uniffi_rustbuffer_reserve()`, `.uniffi_beebeeb_uniffi_fn_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_fn_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_fn_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_fn_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_fn_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_fn_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_fn_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_fn_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_fn_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_fn_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_fn_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_fn_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_fn_func_x25519_shared_secret()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 9`** (19 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 30`** (8 nodes): `NSLock`, `.withLock()`, `UniffiHandleMap`, `.clone()`, `.doInsert()`, `.get()`, `.insert()`, `.remove()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 31`** (8 nodes): `FfiConverter`, `.allocationSize()`, `.lift()`, `.liftFromRustBuffer()`, `.lower()`, `.lowerIntoRustBuffer()`, `.read()`, `.write()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 56`** (3 nodes): `file.rs`, `ChunkMeta`, `EncryptedBlob`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 59`** (2 nodes): `error.rs`, `CoreError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 60`** (2 nodes): `error.rs`, `SyncError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `UniffiLib` connect `Community 3` to `Community 0`?**
  _High betweenness centrality (0.100) - this node is a cross-community bridge._
- **Why does `ok` connect `Community 2` to `Community 1`, `Community 4`, `Community 6`, `Community 8`, `Community 11`?**
  _High betweenness centrality (0.095) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 1` to `Community 2`?**
  _High betweenness centrality (0.063) - this node is a cross-community bridge._
- **Are the 39 inferred relationships involving `ok` (e.g. with `file_key_from_slice()` and `master_key_from_slice()`) actually correct?**
  _`ok` has 39 INFERRED edges - model-reasoned connections that need verification._
- **Are the 17 inferred relationships involving `derive_master_key()` (e.g. with `ok` and `vector_master_key_from_password()`) actually correct?**
  _`derive_master_key()` has 17 INFERRED edges - model-reasoned connections that need verification._
- **Are the 20 inferred relationships involving `derive_file_key()` (e.g. with `ok` and `vector_file_key_derivation()`) actually correct?**
  _`derive_file_key()` has 20 INFERRED edges - model-reasoned connections that need verification._
- **What connects `EncryptedBlob`, `ChunkMeta`, `CipherSuite` to the rest of the system?**
  _56 weakly-connected nodes found - possible documentation gaps or missing edges._