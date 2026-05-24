# Graph Report - core  (2026-05-24)

## Corpus Check
- 109 files · ~185,658 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2434 nodes · 5477 edges · 31 communities detected
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 784 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]

## God Nodes (most connected - your core abstractions)
1. `ok` - 106 edges
2. `UniffiLib` - 85 edges
3. `rustCallWithError()` - 57 edges
4. `rustCallWithError()` - 57 edges
5. `derive_master_key()` - 50 edges
6. `FfiConverterRustBuffer` - 41 edges
7. `FfiConverterRustBuffer` - 41 edges
8. `readInt()` - 35 edges
9. `readInt()` - 35 edges
10. `writeInt()` - 34 edges

## Surprising Connections (you probably didn't know these)
- `row_to_entry()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/fp_cache.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `derive_master_key()` --calls--> `password_derived_key_is_deterministic()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/integration.rs
- `derive_master_key()` --calls--> `test_master_key()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/file_encrypt.rs
- `derive_master_key()` --calls--> `wrong_key_fails_decryption()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/file_encrypt.rs
- `derive_master_key()` --calls--> `test_file_key()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/src/encrypt.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (186): CachedFileEntryData, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode(), createReader(), createWriter() (+178 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (144): UniffiLib, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode(), createReader(), decompressGzip() (+136 more)

### Community 2 - "Community 2"
Cohesion: 0.01
Nodes (104): alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), CryptoException, `decryptChunk`(), Decryption (+96 more)

### Community 3 - "Community 3"
Cohesion: 0.03
Nodes (167): hex(), main(), ArchiveEntryDto, CachedFileEntryData, ChunkPlanResult, compute_recovery_check(), compute_recovery_check_works(), constellation_verify_code() (+159 more)

### Community 4 - "Community 4"
Cohesion: 0.03
Nodes (120): Opaque, InitializationResult, apiChecksumMismatch, contractVersionMismatch, ok, compare(), confirm_code_verifies(), constellation_new_session() (+112 more)

### Community 5 - "Community 5"
Cohesion: 0.02
Nodes (97): AnyObject, ArchiveEntryDto, ChunkPlanResult, ConstellationDecoderHandleProtocol, ConstellationEdgeDto, ConstellationFrameDto, ConstellationNodeDto, ConstellationPayloadDto (+89 more)

### Community 6 - "Community 6"
Cohesion: 0.03
Nodes (50): createWriter(), Data, FfiConverterData, FfiConverterOptionCallbackInterfaceDownloadProgressCallback, FfiConverterOptionCallbackInterfaceFileProgressCallback, FfiConverterOptionCallbackInterfaceUploadProgressCallback, FfiConverterOptionString, FfiConverterOptionTypeCachedFileEntryData (+42 more)

### Community 7 - "Community 7"
Cohesion: 0.08
Nodes (61): create(), Encryption, decrypt_chunk(), decrypt_chunk_raw(), decrypt_chunks_to_file(), decrypt_chunks_to_file_empty(), decrypt_chunks_to_file_roundtrip(), decrypt_chunks_to_file_wrong_key_fails() (+53 more)

### Community 8 - "Community 8"
Cohesion: 0.05
Nodes (40): InvalidResponse, Network, boundaries_minimum_valid_single_chunk(), boundaries_single_chunk(), boundaries_three_chunks_with_remainder(), boundaries_two_equal_chunks(), compute_chunk_boundaries(), decrypt_downloaded_bytes() (+32 more)

### Community 9 - "Community 9"
Cohesion: 0.12
Nodes (48): addToExternrefTable0(), compute_recovery_check(), debugString(), decodeText(), decompress_gzip(), decrypt_chunk(), decrypt_chunks(), decrypt_metadata() (+40 more)

### Community 10 - "Community 10"
Cohesion: 0.12
Nodes (13): op(), string_field(), SyncEngine, test_apply_remote_file_create(), test_apply_remote_file_move(), test_apply_remote_file_rename(), test_echo_suppression(), test_permanent_delete_clears_pin() (+5 more)

### Community 11 - "Community 11"
Cohesion: 0.13
Nodes (16): clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+8 more)

### Community 12 - "Community 12"
Cohesion: 0.12
Nodes (24): Kdf, derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), different_file_ids_yield_different_keys(), different_passwords_yield_different_keys() (+16 more)

### Community 13 - "Community 13"
Cohesion: 0.07
Nodes (1): IntegrityCheckingUniffiLib

### Community 14 - "Community 14"
Cohesion: 0.14
Nodes (22): InvalidInput, empty_data_roundtrip(), parse_encrypted_metadata(), parse_field(), parse_legacy_numeric_arrays(), parse_mixed_formats(), roundtrip_base64(), serialize_encrypted_metadata() (+14 more)

### Community 15 - "Community 15"
Cohesion: 0.21
Nodes (18): Io, CachedFileEntry, clear(), delete_item(), FileProviderCache, folder_entry_properties(), get_children_empty(), get_children_root() (+10 more)

### Community 16 - "Community 16"
Cohesion: 0.15
Nodes (14): approx_text_width(), build_content_stream(), generate_recovery_pdf(), pdf_contains_all_six_objects(), pdf_contains_metadata(), pdf_contains_title(), pdf_contains_words(), pdf_empty_words() (+6 more)

### Community 17 - "Community 17"
Cohesion: 0.17
Nodes (15): BitArray, constellation_encode(), dummy_payload(), encode_shards(), frame_brightness_quantises_to_known_levels(), mix64(), pack_shard(), pack_shard_uses_full_capacity() (+7 more)

### Community 18 - "Community 18"
Cohesion: 0.11
Nodes (2): effective_quota(), Plan

### Community 19 - "Community 19"
Cohesion: 0.1
Nodes (20): UniffiInternalError, bufferOverflow, incompleteData, rustPanic, unexpectedEnumCase, unexpectedNullPointer, unexpectedOptionalTag, unexpectedRustCallError (+12 more)

### Community 20 - "Community 20"
Cohesion: 0.19
Nodes (13): derive_sas(), derive_shared_secret(), derive_transfer_key(), derive_transfer_key_is_deterministic(), fresh_keypairs_yield_different_shared_secrets(), generate_keypair(), key_exchange_roundtrip_yields_same_shared_secret(), sas_is_deterministic() (+5 more)

### Community 23 - "Community 23"
Cohesion: 0.27
Nodes (11): derive_sas_bytes(), derive_sas_bytes_deterministic(), derive_sas_bytes_different_info_differ(), derive_sas_bytes_different_secrets_differ(), derive_sas_bytes_matches_transfer_crypto(), derive_sas_bytes_zero_length(), sha256(), sha256_abc() (+3 more)

### Community 26 - "Community 26"
Cohesion: 0.44
Nodes (9): decrypt_blob(), empty_plaintext_roundtrip(), encrypt_blob(), large_payload(), roundtrip(), tampered_ciphertext_fails(), test_key(), unique_nonces() (+1 more)

### Community 34 - "Community 34"
Cohesion: 0.22
Nodes (7): ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode

### Community 41 - "Community 41"
Cohesion: 0.36
Nodes (5): base_chunk_size(), ChunkPlan, ChunkProfile, ChunkStrategy, plan_chunks()

### Community 55 - "Community 55"
Cohesion: 0.4
Nodes (1): UploadError

### Community 64 - "Community 64"
Cohesion: 0.5
Nodes (3): PendingOp, SyncOp, TreeNode

### Community 69 - "Community 69"
Cohesion: 0.67
Nodes (2): ChunkMeta, EncryptedBlob

### Community 71 - "Community 71"
Cohesion: 1.0
Nodes (1): CoreError

### Community 72 - "Community 72"
Cohesion: 1.0
Nodes (1): SyncEvent

### Community 73 - "Community 73"
Cohesion: 1.0
Nodes (1): SyncError

## Knowledge Gaps
- **131 isolated node(s):** `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag`, `unexpectedEnumCase`, `unexpectedNullPointer` (+126 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 13`** (29 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 18`** (23 nodes): `quota.rs`, `can_add_storage_per_plan()`, `can_add_users_per_plan()`, `effective_quota()`, `effective_quota_capped_at_99_tb()`, `effective_quota_extra_tb_on_pro()`, `effective_quota_ignores_extra_tb_for_free_and_basic()`, `effective_quota_with_bonus_bytes()`, `effective_quota_zero_extra()`, `format_storage_si_various()`, `max_extra_tb_per_plan()`, `max_extra_users_per_plan()`, `monthly_cost_cents_all_plans()`, `monthly_cost_cents_with_addons()`, `Plan`, `.base_storage_bytes()`, `.can_add_storage()`, `.can_add_users()`, `plan_from_slug_all_variants()`, `.max_extra_tb()`, `.max_extra_users()`, `.slug()`, `plan_slug_roundtrip()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 55`** (5 nodes): `error.rs`, `UploadError`, `.fmt()`, `.is_retryable()`, `.retry_after()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 69`** (3 nodes): `file.rs`, `ChunkMeta`, `EncryptedBlob`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 71`** (2 nodes): `error.rs`, `CoreError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 72`** (2 nodes): `events.rs`, `SyncEvent`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 73`** (2 nodes): `error.rs`, `SyncError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ok` connect `Community 4` to `Community 3`, `Community 7`, `Community 8`, `Community 11`, `Community 12`, `Community 14`, `Community 15`, `Community 26`?**
  _High betweenness centrality (0.185) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 4` to `Community 0`?**
  _High betweenness centrality (0.134) - this node is a cross-community bridge._
- **Why does `UniffiLib` connect `Community 1` to `Community 2`?**
  _High betweenness centrality (0.130) - this node is a cross-community bridge._
- **Are the 105 inferred relationships involving `ok` (e.g. with `derive_master_key()` and `derive_file_key()`) actually correct?**
  _`ok` has 105 INFERRED edges - model-reasoned connections that need verification._
- **What connects `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag` to the rest of the system?**
  _131 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._