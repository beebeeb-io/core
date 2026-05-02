# Graph Report - core  (2026-05-02)

## Corpus Check
- 85 files · ~135,345 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1418 nodes · 2829 edges · 27 communities detected
- Extraction: 84% EXTRACTED · 16% INFERRED · 0% AMBIGUOUS · INFERRED: 460 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]

## God Nodes (most connected - your core abstractions)
1. `UniffiLib` - 85 edges
2. `ok` - 44 edges
3. `derive_master_key()` - 34 edges
4. `IntegrityCheckingUniffiLib` - 30 edges
5. `rustCallWithError()` - 29 edges
6. `rustCallWithError()` - 29 edges
7. `SyncEngine` - 27 edges
8. `derive_file_key()` - 26 edges
9. `main()` - 24 edges
10. `encrypt_chunk()` - 20 edges

## Surprising Connections (you probably didn't know these)
- `derive_master_key()` --calls--> `password_derived_key_is_deterministic()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/integration.rs
- `derive_master_key()` --calls--> `test_file_key()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/encrypt.rs
- `derive_master_key()` --calls--> `wrong_key_fails_decryption()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/encrypt.rs
- `derive_master_key()` --calls--> `metadata_wrong_key_fails()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/encrypt.rs
- `derive_file_key()` --calls--> `test_file_key()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/encrypt.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.02
Nodes (72): UniffiLib, computeRecoveryCheck(), createReader(), createWriter(), Data, decryptChunk(), decryptMetadata(), deriveFileKey() (+64 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (102): alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), create(), CryptoException, `decryptChunk`() (+94 more)

### Community 2 - "Community 2"
Cohesion: 0.05
Nodes (117): hex(), main(), ok, loser_filename(), loser_filename_includes_device_and_time(), loser_filename_works_without_extension(), engine_start_stop_lifecycle(), resolve_conflict_keep_both_removes_original() (+109 more)

### Community 3 - "Community 3"
Cohesion: 0.04
Nodes (74): computeRecoveryCheck(), createReader(), createWriter(), Data, decryptChunk(), decryptMetadata(), deriveFileKey(), deriveMasterKey() (+66 more)

### Community 4 - "Community 4"
Cohesion: 0.07
Nodes (36): Opaque, config_new_sets_defaults(), config_roundtrips_through_json(), SyncConfig, SyncMode, CipherSuite, KdfAlgorithm, KdfParams (+28 more)

### Community 5 - "Community 5"
Cohesion: 0.06
Nodes (36): AnyObject, CryptoError, Decryption, Encryption, InvalidInput, InvalidRecoveryPhrase, Kdf, Opaque (+28 more)

### Community 6 - "Community 6"
Cohesion: 0.1
Nodes (24): clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+16 more)

### Community 7 - "Community 7"
Cohesion: 0.12
Nodes (13): op(), string_field(), SyncEngine, test_apply_remote_file_create(), test_apply_remote_file_move(), test_apply_remote_file_rename(), test_echo_suppression(), test_permanent_delete_clears_pin() (+5 more)

### Community 8 - "Community 8"
Cohesion: 0.16
Nodes (34): addToExternrefTable0(), compute_recovery_check(), debugString(), decodeText(), decrypt_chunk(), decrypt_metadata(), derive_file_key(), derive_master_key() (+26 more)

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
Cohesion: 0.31
Nodes (16): Encryption, decrypt_chunk(), decrypt_metadata(), empty_plaintext_roundtrip(), encrypt_chunk(), encrypt_metadata(), invalid_nonce_length_fails(), large_plaintext_roundtrip() (+8 more)

### Community 14 - "Community 14"
Cohesion: 0.23
Nodes (10): selective_from_mode(), calculate_disk_usage(), disk_usage_partitions_files_correctly(), DiskUsage, exclusions_override_inclusions(), FileEntry, full_sync_includes_everything(), online_only_excludes_everything() (+2 more)

### Community 19 - "Community 19"
Cohesion: 0.31
Nodes (9): Conflict, conflict_without_prior_sync_when_timestamps_differ(), ConflictResolution, detect_conflicts(), detects_conflict_when_both_sides_changed(), FileMeta, no_conflict_for_local_only_files(), no_conflict_when_only_local_changed() (+1 more)

### Community 27 - "Community 27"
Cohesion: 0.22
Nodes (7): ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode

### Community 28 - "Community 28"
Cohesion: 0.22
Nodes (1): FileKeyHandle

### Community 29 - "Community 29"
Cohesion: 0.22
Nodes (1): MasterKeyHandle

### Community 36 - "Community 36"
Cohesion: 0.43
Nodes (2): NSLock, UniffiHandleMap

### Community 47 - "Community 47"
Cohesion: 0.33
Nodes (1): FfiConverterTypeFileKeyHandle

### Community 48 - "Community 48"
Cohesion: 0.33
Nodes (1): FfiConverterTypeMasterKeyHandle

### Community 58 - "Community 58"
Cohesion: 0.5
Nodes (3): PendingOp, SyncOp, TreeNode

### Community 64 - "Community 64"
Cohesion: 0.67
Nodes (2): ChunkMeta, EncryptedBlob

### Community 66 - "Community 66"
Cohesion: 1.0
Nodes (1): CoreError

### Community 67 - "Community 67"
Cohesion: 1.0
Nodes (1): SyncEvent

### Community 68 - "Community 68"
Cohesion: 1.0
Nodes (1): SyncError

## Knowledge Gaps
- **74 isolated node(s):** `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag`, `unexpectedEnumCase`, `unexpectedNullPointer` (+69 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 10`** (29 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (9 nodes): `FileKeyHandle`, `.callWithHandle()`, `.close()`, `.`decryptChunk`()`, `.`decryptMetadata`()`, `.destroy()`, `.`encryptChunk`()`, `.`encryptMetadata`()`, `.uniffiCloneHandle()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 29`** (9 nodes): `MasterKeyHandle`, `.callWithHandle()`, `.close()`, `.`computeRecoveryCheck`()`, `.`deriveFileKey`()`, `.`deriveX25519Private`()`, `.destroy()`, `.`exportForKeychain`()`, `.uniffiCloneHandle()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 36`** (8 nodes): `NSLock`, `.withLock()`, `UniffiHandleMap`, `.clone()`, `.doInsert()`, `.get()`, `.insert()`, `.remove()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (6 nodes): `FfiConverterTypeFileKeyHandle`, `.allocationSize()`, `.lift()`, `.lower()`, `.read()`, `.write()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 48`** (6 nodes): `FfiConverterTypeMasterKeyHandle`, `.allocationSize()`, `.lift()`, `.lower()`, `.read()`, `.write()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 64`** (3 nodes): `file.rs`, `ChunkMeta`, `EncryptedBlob`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 66`** (2 nodes): `error.rs`, `CoreError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 67`** (2 nodes): `events.rs`, `SyncEvent`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 68`** (2 nodes): `error.rs`, `SyncError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `UniffiLib` connect `Community 0` to `Community 1`, `Community 3`?**
  _High betweenness centrality (0.151) - this node is a cross-community bridge._
- **Why does `ok` connect `Community 2` to `Community 0`, `Community 4`, `Community 6`, `Community 9`, `Community 13`?**
  _High betweenness centrality (0.137) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 0` to `Community 2`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Are the 43 inferred relationships involving `ok` (e.g. with `derive_master_key()` and `derive_file_key()`) actually correct?**
  _`ok` has 43 INFERRED edges - model-reasoned connections that need verification._
- **Are the 19 inferred relationships involving `derive_master_key()` (e.g. with `.new()` and `.set()`) actually correct?**
  _`derive_master_key()` has 19 INFERRED edges - model-reasoned connections that need verification._
- **What connects `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag` to the rest of the system?**
  _74 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.02 - nodes in this community are weakly interconnected._