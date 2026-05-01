# Graph Report - core  (2026-05-01)

## Corpus Check
- 80 files · ~132,687 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1366 nodes · 2723 edges · 22 communities detected
- Extraction: 83% EXTRACTED · 17% INFERRED · 0% AMBIGUOUS · INFERRED: 459 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]

## God Nodes (most connected - your core abstractions)
1. `UniffiLib` - 85 edges
2. `ok` - 44 edges
3. `derive_master_key()` - 34 edges
4. `IntegrityCheckingUniffiLib` - 30 edges
5. `rustCallWithError()` - 29 edges
6. `rustCallWithError()` - 29 edges
7. `derive_file_key()` - 26 edges
8. `main()` - 24 edges
9. `encrypt_chunk()` - 20 edges
10. `generate_recovery_phrase()` - 20 edges

## Surprising Connections (you probably didn't know these)
- `derive_master_key()` --calls--> `password_derived_key_is_deterministic()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/integration.rs
- `derive_master_key()` --calls--> `x25519_keypair_from_master_key()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/opaque.rs
- `derive_master_key()` --calls--> `x25519_keypair_deterministic()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/opaque.rs
- `derive_master_key()` --calls--> `x25519_dh_shared_secret()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/opaque.rs
- `derive_master_key()` --calls--> `share_key_derivation()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/opaque.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.02
Nodes (75): UniffiLib, computeRecoveryCheck(), createReader(), createWriter(), Data, decryptChunk(), decryptMetadata(), deriveFileKey() (+67 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (103): alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), create(), CryptoException, `decryptChunk`() (+95 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (99): hex(), main(), ok, compute_recovery_check(), compute_recovery_check_works(), constellation_new_session(), constellation_session_roundtrip(), constellation_verify_code() (+91 more)

### Community 3 - "Community 3"
Cohesion: 0.04
Nodes (74): computeRecoveryCheck(), createReader(), createWriter(), Data, decryptChunk(), decryptMetadata(), deriveFileKey(), deriveMasterKey() (+66 more)

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (35): AnyObject, CryptoError, Decryption, Encryption, InvalidInput, InvalidRecoveryPhrase, Kdf, Opaque (+27 more)

### Community 5 - "Community 5"
Cohesion: 0.08
Nodes (34): Opaque, config_new_sets_defaults(), config_roundtrips_through_json(), SyncConfig, SyncMode, CipherSuite, KdfAlgorithm, KdfParams (+26 more)

### Community 6 - "Community 6"
Cohesion: 0.08
Nodes (30): Conflict, conflict_without_prior_sync_when_timestamps_differ(), ConflictResolution, detect_conflicts(), detects_conflict_when_both_sides_changed(), FileMeta, loser_filename(), loser_filename_includes_device_and_time() (+22 more)

### Community 7 - "Community 7"
Cohesion: 0.16
Nodes (34): addToExternrefTable0(), compute_recovery_check(), debugString(), decodeText(), decrypt_chunk(), decrypt_metadata(), derive_file_key(), derive_master_key() (+26 more)

### Community 8 - "Community 8"
Cohesion: 0.14
Nodes (20): clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+12 more)

### Community 9 - "Community 9"
Cohesion: 0.12
Nodes (24): Kdf, derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), different_file_ids_yield_different_keys(), different_passwords_yield_different_keys() (+16 more)

### Community 10 - "Community 10"
Cohesion: 0.07
Nodes (1): IntegrityCheckingUniffiLib

### Community 11 - "Community 11"
Cohesion: 0.17
Nodes (15): BitArray, constellation_encode(), dummy_payload(), encode_shards(), frame_brightness_quantises_to_known_levels(), mix64(), pack_shard(), pack_shard_uses_full_capacity() (+7 more)

### Community 12 - "Community 12"
Cohesion: 0.1
Nodes (21): UniffiInternalError, bufferOverflow, incompleteData, rustPanic, unexpectedEnumCase, unexpectedNullPointer, unexpectedOptionalTag, unexpectedRustCallError (+13 more)

### Community 13 - "Community 13"
Cohesion: 0.23
Nodes (13): compute_recovery_check(), derive_share_key(), derive_x25519_private(), derive_x25519_public(), envelope_round_trip(), OpaqueEnvelope, recovery_check_deterministic(), share_key_derivation() (+5 more)

### Community 14 - "Community 14"
Cohesion: 0.31
Nodes (16): Encryption, decrypt_chunk(), decrypt_metadata(), empty_plaintext_roundtrip(), encrypt_chunk(), encrypt_metadata(), invalid_nonce_length_fails(), large_plaintext_roundtrip() (+8 more)

### Community 26 - "Community 26"
Cohesion: 0.22
Nodes (7): ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode

### Community 27 - "Community 27"
Cohesion: 0.22
Nodes (1): FileKeyHandle

### Community 28 - "Community 28"
Cohesion: 0.22
Nodes (1): MasterKeyHandle

### Community 45 - "Community 45"
Cohesion: 0.33
Nodes (1): FfiConverterTypeMasterKeyHandle

### Community 59 - "Community 59"
Cohesion: 0.67
Nodes (2): ChunkMeta, EncryptedBlob

### Community 61 - "Community 61"
Cohesion: 1.0
Nodes (1): CoreError

### Community 62 - "Community 62"
Cohesion: 1.0
Nodes (1): SyncError

## Knowledge Gaps
- **70 isolated node(s):** `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag`, `unexpectedEnumCase`, `unexpectedNullPointer` (+65 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 10`** (29 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 27`** (9 nodes): `FileKeyHandle`, `.callWithHandle()`, `.close()`, `.`decryptChunk`()`, `.`decryptMetadata`()`, `.destroy()`, `.`encryptChunk`()`, `.`encryptMetadata`()`, `.uniffiCloneHandle()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (9 nodes): `MasterKeyHandle`, `.callWithHandle()`, `.close()`, `.`computeRecoveryCheck`()`, `.`deriveFileKey`()`, `.`deriveX25519Private`()`, `.destroy()`, `.`exportForKeychain`()`, `.uniffiCloneHandle()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (6 nodes): `FfiConverterTypeMasterKeyHandle`, `.allocationSize()`, `.lift()`, `.lower()`, `.read()`, `.write()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 59`** (3 nodes): `file.rs`, `ChunkMeta`, `EncryptedBlob`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 61`** (2 nodes): `error.rs`, `CoreError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 62`** (2 nodes): `error.rs`, `SyncError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `UniffiLib` connect `Community 0` to `Community 1`?**
  _High betweenness centrality (0.151) - this node is a cross-community bridge._
- **Why does `ok` connect `Community 2` to `Community 3`, `Community 5`, `Community 6`, `Community 8`, `Community 9`, `Community 14`?**
  _High betweenness centrality (0.142) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 3` to `Community 2`?**
  _High betweenness centrality (0.110) - this node is a cross-community bridge._
- **Are the 43 inferred relationships involving `ok` (e.g. with `derive_master_key()` and `derive_file_key()`) actually correct?**
  _`ok` has 43 INFERRED edges - model-reasoned connections that need verification._
- **Are the 19 inferred relationships involving `derive_master_key()` (e.g. with `.new()` and `.set()`) actually correct?**
  _`derive_master_key()` has 19 INFERRED edges - model-reasoned connections that need verification._
- **What connects `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag` to the rest of the system?**
  _70 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.02 - nodes in this community are weakly interconnected._