# Graph Report - core  (2026-05-31)

## Corpus Check
- 113 files · ~206,693 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2725 nodes · 6450 edges · 39 communities detected
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 931 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]
- [[_COMMUNITY_Community 81|Community 81]]

## God Nodes (most connected - your core abstractions)
1. `ok` - 149 edges
2. `UniffiLib` - 85 edges
3. `rustCallWithError()` - 70 edges
4. `derive_master_key()` - 62 edges
5. `rustCallWithError()` - 58 edges
6. `FfiConverterRustBuffer` - 48 edges
7. `FfiConverterRustBuffer` - 43 edges
8. `readInt()` - 40 edges
9. `writeInt()` - 39 edges
10. `rustCall()` - 37 edges

## Surprising Connections (you probably didn't know these)
- `n32_ladder_vectors_hold_for_backup_profile()` --calls--> `plan_chunks()`  [INFERRED]
  beebeeb-types/tests/chunk_planning.rs → beebeeb-uniffi/src/lib.rs
- `zero_and_one_byte_are_single_4mib_chunks()` --calls--> `plan_chunks()`  [INFERRED]
  beebeeb-types/tests/chunk_planning.rs → beebeeb-uniffi/src/lib.rs
- `static_caps_per_profile()` --calls--> `plan_chunks()`  [INFERRED]
  beebeeb-types/tests/chunk_planning.rs → beebeeb-uniffi/src/lib.rs
- `row_to_entry()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/fp_cache.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `derive_master_key()` --calls--> `vector_master_key_from_password()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/cross_platform_vectors.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (215): ArchiveEntryDto, CachedFileEntryData, ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession() (+207 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (196): computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode(), createReader(), createWriter(), Data (+188 more)

### Community 2 - "Community 2"
Cohesion: 0.02
Nodes (226): hex(), main(), ok, config_new_sets_defaults(), config_roundtrips_through_json(), engine_start_stop_lifecycle(), resolve_conflict_keep_both_removes_original(), resolve_conflict_keep_local_preserves_both() (+218 more)

### Community 3 - "Community 3"
Cohesion: 0.01
Nodes (103): alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), CryptoException, `decryptChunk`(), Decryption (+95 more)

### Community 4 - "Community 4"
Cohesion: 0.02
Nodes (108): AnyObject, ChunkDecryptorHandleProtocol, ChunkEncryptorHandleProtocol, ChunkEncryptorSummaryDto, ChunkPlanResult, ConstellationDecoderHandleProtocol, ConstellationEdgeDto, ConstellationFrameDto (+100 more)

### Community 5 - "Community 5"
Cohesion: 0.03
Nodes (115): create(), Encryption, FfiConverterTypeCryptoError, InvalidResponse, Network, boundaries_minimum_valid_single_chunk(), boundaries_single_chunk(), boundaries_three_chunks_with_remainder() (+107 more)

### Community 6 - "Community 6"
Cohesion: 0.02
Nodes (1): UniffiLib

### Community 7 - "Community 7"
Cohesion: 0.06
Nodes (51): Opaque, ArchiveEntry, build_tar(), decompress_gzip(), gzip_invalid_data(), gzip_roundtrip(), list_archive(), list_archive_plain_gz() (+43 more)

### Community 8 - "Community 8"
Cohesion: 0.08
Nodes (44): InvalidInput, ChunkDecryptor, ChunkEncryptor, ChunkEncryptorSummary, CountingReader, decrypt_frames(), DecryptedChunk, decryptor_chunk_size_zero_errors() (+36 more)

### Community 9 - "Community 9"
Cohesion: 0.1
Nodes (56): addHeapObject(), compute_recovery_check(), debugString(), decodeText(), decompress_gzip(), decrypt_chunk(), decrypt_chunks(), decrypt_metadata() (+48 more)

### Community 10 - "Community 10"
Cohesion: 0.12
Nodes (13): op(), string_field(), SyncEngine, test_apply_remote_file_create(), test_apply_remote_file_move(), test_apply_remote_file_rename(), test_echo_suppression(), test_permanent_delete_clears_pin() (+5 more)

### Community 11 - "Community 11"
Cohesion: 0.14
Nodes (20): clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+12 more)

### Community 12 - "Community 12"
Cohesion: 0.12
Nodes (24): Kdf, derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), different_file_ids_yield_different_keys(), different_passwords_yield_different_keys() (+16 more)

### Community 13 - "Community 13"
Cohesion: 0.16
Nodes (20): Io, CachedFileEntry, clear(), delete_item(), FileProviderCache, folder_entry_properties(), get_children_empty(), get_children_root() (+12 more)

### Community 14 - "Community 14"
Cohesion: 0.07
Nodes (1): IntegrityCheckingUniffiLib

### Community 15 - "Community 15"
Cohesion: 0.22
Nodes (22): derive_request_wrap_key(), derive_request_wrap_key_deterministic(), derive_request_wrap_key_varies_by_request_id(), derive_seal_key(), each_seal_uses_a_fresh_ephemeral_key(), full_owner_uploader_pipeline(), open_rejects_low_order_ephemeral_public(), open_rejects_tampered_wrapped_key() (+14 more)

### Community 16 - "Community 16"
Cohesion: 0.1
Nodes (3): plan_effective_quota(), effective_quota(), Plan

### Community 17 - "Community 17"
Cohesion: 0.15
Nodes (14): approx_text_width(), build_content_stream(), generate_recovery_pdf(), pdf_contains_all_six_objects(), pdf_contains_metadata(), pdf_contains_title(), pdf_contains_words(), pdf_empty_words() (+6 more)

### Community 18 - "Community 18"
Cohesion: 0.2
Nodes (19): ResizeFailed, aspect_ratio_preserved_landscape(), aspect_ratio_preserved_portrait(), encode_webp(), generate_thumbnail(), LadderStep, large_config_produces_output(), make_test_rgba() (+11 more)

### Community 19 - "Community 19"
Cohesion: 0.17
Nodes (15): BitArray, constellation_encode(), dummy_payload(), encode_shards(), frame_brightness_quantises_to_known_levels(), mix64(), pack_shard(), pack_shard_uses_full_capacity() (+7 more)

### Community 20 - "Community 20"
Cohesion: 0.1
Nodes (21): UniffiInternalError, bufferOverflow, incompleteData, rustPanic, unexpectedEnumCase, unexpectedNullPointer, unexpectedOptionalTag, unexpectedRustCallError (+13 more)

### Community 21 - "Community 21"
Cohesion: 0.19
Nodes (12): derive_sas(), derive_shared_secret(), derive_transfer_key(), derive_transfer_key_is_deterministic(), fresh_keypairs_yield_different_shared_secrets(), key_exchange_roundtrip_yields_same_shared_secret(), sas_is_deterministic(), sas_to_words() (+4 more)

### Community 22 - "Community 22"
Cohesion: 0.31
Nodes (13): bundle_files(), empty_bundle_roundtrip(), empty_file_roundtrip(), header_with_huge_count_does_not_oom(), invalid_utf8_filename_returns_error(), read_slice(), read_u32(), read_u64() (+5 more)

### Community 23 - "Community 23"
Cohesion: 0.26
Nodes (12): Conflict, conflict_without_prior_sync_when_timestamps_differ(), ConflictResolution, detect_conflicts(), detects_conflict_when_both_sides_changed(), FileMeta, loser_filename(), loser_filename_includes_device_and_time() (+4 more)

### Community 24 - "Community 24"
Cohesion: 0.25
Nodes (12): base_chunk_size(), ChunkPlan, ChunkProfile, ChunkStrategy, div_ceil_u64(), effective_cap(), max_plaintext_chunk_bytes(), next_pow2() (+4 more)

### Community 27 - "Community 27"
Cohesion: 0.27
Nodes (11): derive_sas_bytes(), derive_sas_bytes_deterministic(), derive_sas_bytes_different_info_differ(), derive_sas_bytes_different_secrets_differ(), derive_sas_bytes_matches_transfer_crypto(), derive_sas_bytes_zero_length(), sha256(), sha256_abc() (+3 more)

### Community 30 - "Community 30"
Cohesion: 0.44
Nodes (9): decrypt_blob(), empty_plaintext_roundtrip(), encrypt_blob(), large_payload(), roundtrip(), tampered_ciphertext_fails(), test_key(), unique_nonces() (+1 more)

### Community 35 - "Community 35"
Cohesion: 0.4
Nodes (8): decrypt_transfer(), empty_plaintext_roundtrip(), encrypt_transfer(), large_plaintext_roundtrip(), nonces_are_unique_across_encryptions(), roundtrip_encrypt_decrypt(), tampered_ciphertext_fails(), wrong_key_fails_decryption()

### Community 39 - "Community 39"
Cohesion: 0.22
Nodes (7): ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode

### Community 46 - "Community 46"
Cohesion: 0.25
Nodes (3): n32_ladder_vectors_hold_for_backup_profile(), static_caps_per_profile(), zero_and_one_byte_are_single_4mib_chunks()

### Community 47 - "Community 47"
Cohesion: 0.29
Nodes (2): DownloadCallbackBridge, UploadCallbackBridge

### Community 61 - "Community 61"
Cohesion: 0.4
Nodes (1): UploadError

### Community 62 - "Community 62"
Cohesion: 0.5
Nodes (4): InitializationResult, apiChecksumMismatch, contractVersionMismatch, ok

### Community 71 - "Community 71"
Cohesion: 0.5
Nodes (3): PendingOp, SyncOp, TreeNode

### Community 76 - "Community 76"
Cohesion: 0.67
Nodes (2): ChunkMeta, EncryptedBlob

### Community 78 - "Community 78"
Cohesion: 1.0
Nodes (1): WasmChunkEncryptor

### Community 79 - "Community 79"
Cohesion: 1.0
Nodes (1): CoreError

### Community 80 - "Community 80"
Cohesion: 1.0
Nodes (1): SyncEvent

### Community 81 - "Community 81"
Cohesion: 1.0
Nodes (1): SyncError

## Knowledge Gaps
- **157 isolated node(s):** `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag`, `unexpectedEnumCase`, `unexpectedNullPointer` (+152 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 6`** (83 nodes): `UniffiLib`, `.ffi_beebeeb_uniffi_rust_future_cancel_f32()`, `.ffi_beebeeb_uniffi_rust_future_cancel_f64()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i16()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i32()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i64()`, `.ffi_beebeeb_uniffi_rust_future_cancel_i8()`, `.ffi_beebeeb_uniffi_rust_future_cancel_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u16()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u32()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u64()`, `.ffi_beebeeb_uniffi_rust_future_cancel_u8()`, `.ffi_beebeeb_uniffi_rust_future_cancel_void()`, `.ffi_beebeeb_uniffi_rust_future_complete_f32()`, `.ffi_beebeeb_uniffi_rust_future_complete_f64()`, `.ffi_beebeeb_uniffi_rust_future_complete_i16()`, `.ffi_beebeeb_uniffi_rust_future_complete_i32()`, `.ffi_beebeeb_uniffi_rust_future_complete_i64()`, `.ffi_beebeeb_uniffi_rust_future_complete_i8()`, `.ffi_beebeeb_uniffi_rust_future_complete_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_complete_u16()`, `.ffi_beebeeb_uniffi_rust_future_complete_u32()`, `.ffi_beebeeb_uniffi_rust_future_complete_u64()`, `.ffi_beebeeb_uniffi_rust_future_complete_u8()`, `.ffi_beebeeb_uniffi_rust_future_complete_void()`, `.ffi_beebeeb_uniffi_rust_future_free_f32()`, `.ffi_beebeeb_uniffi_rust_future_free_f64()`, `.ffi_beebeeb_uniffi_rust_future_free_i16()`, `.ffi_beebeeb_uniffi_rust_future_free_i32()`, `.ffi_beebeeb_uniffi_rust_future_free_i64()`, `.ffi_beebeeb_uniffi_rust_future_free_i8()`, `.ffi_beebeeb_uniffi_rust_future_free_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_free_u16()`, `.ffi_beebeeb_uniffi_rust_future_free_u32()`, `.ffi_beebeeb_uniffi_rust_future_free_u64()`, `.ffi_beebeeb_uniffi_rust_future_free_u8()`, `.ffi_beebeeb_uniffi_rust_future_free_void()`, `.ffi_beebeeb_uniffi_rust_future_poll_f32()`, `.ffi_beebeeb_uniffi_rust_future_poll_f64()`, `.ffi_beebeeb_uniffi_rust_future_poll_i16()`, `.ffi_beebeeb_uniffi_rust_future_poll_i32()`, `.ffi_beebeeb_uniffi_rust_future_poll_i64()`, `.ffi_beebeeb_uniffi_rust_future_poll_i8()`, `.ffi_beebeeb_uniffi_rust_future_poll_rust_buffer()`, `.ffi_beebeeb_uniffi_rust_future_poll_u16()`, `.ffi_beebeeb_uniffi_rust_future_poll_u32()`, `.ffi_beebeeb_uniffi_rust_future_poll_u64()`, `.ffi_beebeeb_uniffi_rust_future_poll_u8()`, `.ffi_beebeeb_uniffi_rust_future_poll_void()`, `.ffi_beebeeb_uniffi_rustbuffer_alloc()`, `.ffi_beebeeb_uniffi_rustbuffer_free()`, `.ffi_beebeeb_uniffi_rustbuffer_reserve()`, `.uniffi_beebeeb_uniffi_fn_clone_filekeyhandle()`, `.uniffi_beebeeb_uniffi_fn_clone_masterkeyhandle()`, `.uniffi_beebeeb_uniffi_fn_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_fn_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_fn_free_filekeyhandle()`, `.uniffi_beebeeb_uniffi_fn_free_masterkeyhandle()`, `.uniffi_beebeeb_uniffi_fn_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_fn_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_fn_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_fn_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_fn_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_fn_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_fn_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_fn_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_fn_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_fn_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_fn_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_fn_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_fn_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_fn_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_fn_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_fn_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_fn_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_fn_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_fn_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_fn_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_fn_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_fn_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 14`** (29 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (8 nodes): `DownloadCallbackBridge`, `.on_chunk_decrypted()`, `.on_complete()`, `.on_error()`, `UploadCallbackBridge`, `.on_chunk_uploaded()`, `.on_complete()`, `.on_error()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 61`** (5 nodes): `error.rs`, `UploadError`, `.fmt()`, `.is_retryable()`, `.retry_after()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 76`** (3 nodes): `file.rs`, `ChunkMeta`, `EncryptedBlob`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 78`** (2 nodes): `beebeeb_wasm.d.ts`, `WasmChunkEncryptor`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 79`** (2 nodes): `error.rs`, `CoreError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 80`** (2 nodes): `events.rs`, `SyncEvent`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 81`** (2 nodes): `error.rs`, `SyncError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ok` connect `Community 2` to `Community 0`, `Community 35`, `Community 5`, `Community 7`, `Community 8`, `Community 11`, `Community 12`, `Community 13`, `Community 15`, `Community 18`, `Community 22`, `Community 30`?**
  _High betweenness centrality (0.218) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 0` to `Community 2`?**
  _High betweenness centrality (0.144) - this node is a cross-community bridge._
- **Why does `UniffiLib` connect `Community 6` to `Community 1`, `Community 3`?**
  _High betweenness centrality (0.122) - this node is a cross-community bridge._
- **Are the 148 inferred relationships involving `ok` (e.g. with `derive_master_key()` and `derive_file_key()`) actually correct?**
  _`ok` has 148 INFERRED edges - model-reasoned connections that need verification._
- **Are the 37 inferred relationships involving `derive_master_key()` (e.g. with `.set()` and `.from()`) actually correct?**
  _`derive_master_key()` has 37 INFERRED edges - model-reasoned connections that need verification._
- **What connects `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag` to the rest of the system?**
  _157 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._