# Graph Report - core  (2026-06-24)

## Corpus Check
- 116 files · ~226,293 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2999 nodes · 7323 edges · 38 communities detected
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 1112 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]

## God Nodes (most connected - your core abstractions)
1. `ok` - 170 edges
2. `UniffiLib` - 85 edges
3. `rustCallWithError()` - 75 edges
4. `rustCallWithError()` - 75 edges
5. `derive_master_key()` - 69 edges
6. `FfiConverterRustBuffer` - 50 edges
7. `FfiConverterRustBuffer` - 50 edges
8. `readInt()` - 40 edges
9. `readInt()` - 40 edges
10. `writeInt()` - 39 edges

## Surprising Connections (you probably didn't know these)
- `derive_master_key()` --calls--> `password_derived_key_is_deterministic()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/integration.rs
- `decrypt_names_empty_input()` --calls--> `derive_master_key()`  [INFERRED]
  beebeeb-core/src/encrypt.rs → beebeeb-uniffi/src/lib.rs
- `recover_from_phrase()` --calls--> `invalid_recovery_phrase_is_rejected()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/integration.rs
- `plan_chunks()` --calls--> `n32_ladder_vectors_hold_for_backup_profile()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-types/tests/chunk_planning.rs
- `plan_chunks()` --calls--> `zero_and_one_byte_are_single_4mib_chunks()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-types/tests/chunk_planning.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (226): UniffiLib, ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode() (+218 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (225): ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), ConstellationFrameDto, constellationNewSession(), constellationVerifyCode() (+217 more)

### Community 2 - "Community 2"
Cohesion: 0.01
Nodes (280): hex(), main(), ok, edge_pairs(), compare(), confirm_code_verifies(), constellation_new_session(), constellation_verify_code() (+272 more)

### Community 3 - "Community 3"
Cohesion: 0.01
Nodes (104): alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), CryptoException, `decryptChunk`(), Decryption (+96 more)

### Community 4 - "Community 4"
Cohesion: 0.02
Nodes (121): AnyObject, ArchiveEntryDto, CachedFileEntryData, ChunkDecryptorHandleProtocol, ChunkEncryptorHandleProtocol, ChunkEncryptorSummaryDto, ChunkPlanResult, ConstellationDecoderHandleProtocol (+113 more)

### Community 5 - "Community 5"
Cohesion: 0.04
Nodes (106): create(), Encryption, FfiConverterTypeCryptoError, InvalidResponse, Network, boundaries_minimum_valid_single_chunk(), boundaries_single_chunk(), boundaries_three_chunks_with_remainder() (+98 more)

### Community 6 - "Community 6"
Cohesion: 0.08
Nodes (66): ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode, decrypt_chunk() (+58 more)

### Community 7 - "Community 7"
Cohesion: 0.08
Nodes (47): InvalidInput, check_explicit_chunk_size(), ChunkDecryptor, ChunkEncryptor, ChunkEncryptorSummary, CountingReader, decrypt_frames(), DecryptedChunk (+39 more)

### Community 8 - "Community 8"
Cohesion: 0.06
Nodes (50): Opaque, SyncConfig, SyncMode, CipherSuite, KdfAlgorithm, KdfParams, Argon2idKsf, BeebeebCs (+42 more)

### Community 9 - "Community 9"
Cohesion: 0.1
Nodes (57): addHeapObject(), compute_recovery_check(), debugString(), decodeText(), decompress_gzip(), decrypt_chunk(), decrypt_chunks(), decrypt_metadata() (+49 more)

### Community 10 - "Community 10"
Cohesion: 0.1
Nodes (37): bucket_is_deterministic_and_bounded(), bucket_of(), BucketData, delete_touches_only_affected_shards_and_removes(), encrypt_decrypt_roundtrip_preserves_queries(), EncryptedShard, est_file(), est_posting() (+29 more)

### Community 11 - "Community 11"
Cohesion: 0.1
Nodes (26): clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+18 more)

### Community 12 - "Community 12"
Cohesion: 0.12
Nodes (13): op(), string_field(), SyncEngine, test_apply_remote_file_create(), test_apply_remote_file_move(), test_apply_remote_file_rename(), test_echo_suppression(), test_permanent_delete_clears_pin() (+5 more)

### Community 13 - "Community 13"
Cohesion: 0.11
Nodes (24): full_transfer_roundtrip_both_sides_agree(), sas_agrees_both_sides_and_detects_mitm(), sas_bytes_match_fixed_vector(), transfer_key_matches_fixed_vector(), derive_shared_secret(), derive_transfer_key(), derive_transfer_key_is_deterministic(), fresh_keypairs_yield_different_shared_secrets() (+16 more)

### Community 14 - "Community 14"
Cohesion: 0.07
Nodes (1): IntegrityCheckingUniffiLib

### Community 15 - "Community 15"
Cohesion: 0.21
Nodes (18): Io, CachedFileEntry, clear(), delete_item(), FileProviderCache, folder_entry_properties(), get_children_empty(), get_children_root() (+10 more)

### Community 16 - "Community 16"
Cohesion: 0.1
Nodes (5): plan_effective_quota(), plan_monthly_cost_cents(), effective_quota(), monthly_cost_cents(), Plan

### Community 17 - "Community 17"
Cohesion: 0.16
Nodes (19): derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), derive_search_index_key(), different_file_ids_yield_different_keys(), different_passwords_yield_different_keys() (+11 more)

### Community 18 - "Community 18"
Cohesion: 0.22
Nodes (22): derive_request_wrap_key(), derive_request_wrap_key_deterministic(), derive_request_wrap_key_varies_by_request_id(), derive_seal_key(), each_seal_uses_a_fresh_ephemeral_key(), full_owner_uploader_pipeline(), open_rejects_low_order_ephemeral_public(), open_rejects_tampered_wrapped_key() (+14 more)

### Community 19 - "Community 19"
Cohesion: 0.16
Nodes (14): approx_text_width(), build_content_stream(), generate_recovery_pdf(), pdf_contains_all_six_objects(), pdf_contains_metadata(), pdf_contains_title(), pdf_contains_words(), pdf_empty_words() (+6 more)

### Community 20 - "Community 20"
Cohesion: 0.21
Nodes (18): aspect_ratio_preserved_landscape(), aspect_ratio_preserved_portrait(), encode_webp(), generate_thumbnail(), LadderStep, large_config_produces_output(), make_test_rgba(), medium_config_produces_output() (+10 more)

### Community 21 - "Community 21"
Cohesion: 0.1
Nodes (20): UniffiInternalError, bufferOverflow, incompleteData, rustPanic, unexpectedEnumCase, unexpectedNullPointer, unexpectedOptionalTag, unexpectedRustCallError (+12 more)

### Community 22 - "Community 22"
Cohesion: 0.25
Nodes (12): base_chunk_size(), ChunkPlan, ChunkProfile, ChunkStrategy, div_ceil_u64(), effective_cap(), max_plaintext_chunk_bytes(), next_pow2() (+4 more)

### Community 25 - "Community 25"
Cohesion: 0.27
Nodes (11): derive_sas_bytes(), derive_sas_bytes_deterministic(), derive_sas_bytes_different_info_differ(), derive_sas_bytes_different_secrets_differ(), derive_sas_bytes_matches_transfer_crypto(), derive_sas_bytes_zero_length(), sha256(), sha256_abc() (+3 more)

### Community 27 - "Community 27"
Cohesion: 0.39
Nodes (11): bundle_files(), empty_bundle_roundtrip(), empty_file_roundtrip(), read_slice(), read_u32(), read_u64(), roundtrip_three_files(), trailing_bytes_return_error() (+3 more)

### Community 29 - "Community 29"
Cohesion: 0.44
Nodes (9): decrypt_blob(), empty_plaintext_roundtrip(), encrypt_blob(), large_payload(), roundtrip(), tampered_ciphertext_fails(), test_key(), unique_nonces() (+1 more)

### Community 34 - "Community 34"
Cohesion: 0.4
Nodes (9): each_generation_produces_unique_phrase(), empty_phrase_returns_error(), entropy_zeroizing_preserves_roundtrip(), generate_recovery_phrase(), invalid_phrase_returns_error(), known_phrase_deterministic(), recover_from_phrase(), recovery_phrase_roundtrip() (+1 more)

### Community 44 - "Community 44"
Cohesion: 0.25
Nodes (3): n32_ladder_vectors_hold_for_backup_profile(), static_caps_per_profile(), zero_and_one_byte_are_single_4mib_chunks()

### Community 45 - "Community 45"
Cohesion: 0.29
Nodes (2): DownloadCallbackBridge, UploadCallbackBridge

### Community 59 - "Community 59"
Cohesion: 0.4
Nodes (1): UploadError

### Community 67 - "Community 67"
Cohesion: 0.5
Nodes (2): ZipEntry, ZipProgress

### Community 69 - "Community 69"
Cohesion: 0.5
Nodes (3): PendingOp, SyncOp, TreeNode

### Community 70 - "Community 70"
Cohesion: 0.5
Nodes (1): blake3_hash()

### Community 75 - "Community 75"
Cohesion: 0.67
Nodes (2): ChunkMeta, EncryptedBlob

### Community 77 - "Community 77"
Cohesion: 1.0
Nodes (1): WasmChunkEncryptor

### Community 78 - "Community 78"
Cohesion: 1.0
Nodes (1): CoreError

### Community 79 - "Community 79"
Cohesion: 1.0
Nodes (1): SyncEvent

### Community 80 - "Community 80"
Cohesion: 1.0
Nodes (1): SyncError

## Knowledge Gaps
- **176 isolated node(s):** `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag`, `unexpectedEnumCase`, `unexpectedNullPointer` (+171 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 14`** (29 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (8 nodes): `DownloadCallbackBridge`, `.on_chunk_decrypted()`, `.on_complete()`, `.on_error()`, `UploadCallbackBridge`, `.on_chunk_uploaded()`, `.on_complete()`, `.on_error()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 59`** (5 nodes): `error.rs`, `UploadError`, `.fmt()`, `.is_retryable()`, `.retry_after()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 67`** (4 nodes): `zip.rs`, `estimate_zip_size()`, `ZipEntry`, `ZipProgress`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 70`** (4 nodes): `hash.rs`, `blake3_hash()`, `deterministic()`, `empty_input_has_known_hash()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 75`** (3 nodes): `file.rs`, `ChunkMeta`, `EncryptedBlob`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 77`** (2 nodes): `beebeeb_wasm.d.ts`, `WasmChunkEncryptor`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 78`** (2 nodes): `error.rs`, `CoreError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 79`** (2 nodes): `events.rs`, `SyncEvent`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 80`** (2 nodes): `error.rs`, `SyncError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ok` connect `Community 2` to `Community 1`, `Community 34`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 10`, `Community 11`, `Community 13`, `Community 15`, `Community 17`, `Community 18`, `Community 20`, `Community 27`, `Community 29`?**
  _High betweenness centrality (0.243) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 1` to `Community 2`?**
  _High betweenness centrality (0.158) - this node is a cross-community bridge._
- **Why does `UniffiLib` connect `Community 0` to `Community 3`?**
  _High betweenness centrality (0.096) - this node is a cross-community bridge._
- **Are the 169 inferred relationships involving `ok` (e.g. with `derive_master_key()` and `derive_file_key()`) actually correct?**
  _`ok` has 169 INFERRED edges - model-reasoned connections that need verification._
- **What connects `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag` to the rest of the system?**
  _176 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._