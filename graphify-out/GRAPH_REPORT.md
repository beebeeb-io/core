# Graph Report - core  (2026-06-25)

## Corpus Check
- 118 files · ~228,578 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 3034 nodes · 7421 edges · 34 communities detected
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 1129 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]

## God Nodes (most connected - your core abstractions)
1. `ok` - 172 edges
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
- `row_to_entry()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/fp_cache.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `upload_error_display()` --calls--> `Network`  [INFERRED]
  beebeeb-upload/src/tests.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `derive_master_key()` --calls--> `file_encrypt_matches_direct_chunk_encryptor_loop()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/chunk_stream_parity.rs
- `derive_master_key()` --calls--> `file_encrypt_empty_file_parity()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/chunk_stream_parity.rs
- `derive_master_key()` --calls--> `password_derived_key_is_deterministic()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/integration.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (226): UniffiLib, ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode() (+218 more)

### Community 1 - "Community 1"
Cohesion: 0.01
Nodes (221): ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode(), createReader() (+213 more)

### Community 2 - "Community 2"
Cohesion: 0.02
Nodes (230): hex(), main(), InitializationResult, apiChecksumMismatch, contractVersionMismatch, ok, decrypt_names_empty_input(), archive_entries_to_js() (+222 more)

### Community 3 - "Community 3"
Cohesion: 0.02
Nodes (162): Opaque, compare(), confirm_code_verifies(), constellation_new_session(), constellation_verify_code(), distinct_sessions_differ(), full_pairing_roundtrip(), hash_confirm_code() (+154 more)

### Community 4 - "Community 4"
Cohesion: 0.01
Nodes (103): alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), CryptoException, `decryptChunk`(), Decryption (+95 more)

### Community 5 - "Community 5"
Cohesion: 0.02
Nodes (120): AnyObject, ArchiveEntryDto, CachedFileEntryData, ChunkDecryptorHandleProtocol, ChunkEncryptorHandleProtocol, ChunkEncryptorSummaryDto, ChunkPlanResult, ConstellationDecoderHandleProtocol (+112 more)

### Community 6 - "Community 6"
Cohesion: 0.04
Nodes (102): create(), Encryption, FfiConverterTypeCryptoError, InvalidResponse, Network, boundaries_minimum_valid_single_chunk(), boundaries_single_chunk(), boundaries_three_chunks_with_remainder() (+94 more)

### Community 7 - "Community 7"
Cohesion: 0.08
Nodes (47): InvalidInput, check_explicit_chunk_size(), ChunkDecryptor, ChunkEncryptor, ChunkEncryptorSummary, CountingReader, decrypt_frames(), DecryptedChunk (+39 more)

### Community 8 - "Community 8"
Cohesion: 0.1
Nodes (57): addHeapObject(), compute_recovery_check(), debugString(), decodeText(), decompress_gzip(), decrypt_chunk(), decrypt_chunks(), decrypt_metadata() (+49 more)

### Community 9 - "Community 9"
Cohesion: 0.07
Nodes (31): clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+23 more)

### Community 10 - "Community 10"
Cohesion: 0.1
Nodes (37): bucket_is_deterministic_and_bounded(), bucket_of(), BucketData, delete_touches_only_affected_shards_and_removes(), encrypt_decrypt_roundtrip_preserves_queries(), EncryptedShard, est_file(), est_posting() (+29 more)

### Community 11 - "Community 11"
Cohesion: 0.12
Nodes (13): op(), string_field(), SyncEngine, test_apply_remote_file_create(), test_apply_remote_file_move(), test_apply_remote_file_rename(), test_echo_suppression(), test_permanent_delete_clears_pin() (+5 more)

### Community 12 - "Community 12"
Cohesion: 0.11
Nodes (30): Kdf, derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), derive_search_index_key(), different_file_ids_yield_different_keys() (+22 more)

### Community 13 - "Community 13"
Cohesion: 0.14
Nodes (27): Io, decrypt_blob(), empty_plaintext_roundtrip(), encrypt_blob(), large_payload(), roundtrip(), tampered_ciphertext_fails(), test_key() (+19 more)

### Community 14 - "Community 14"
Cohesion: 0.14
Nodes (26): aes_gcm_decrypt(), bad_nonce_length_is_rejected(), both_sides_derive_the_same_shared_secret(), browser_encrypt(), CliEphemeralKey, decrypt_cli_payload(), derive_cli_auth_key(), derive_cli_auth_key_varies_by_secret() (+18 more)

### Community 15 - "Community 15"
Cohesion: 0.1
Nodes (28): derive_sas_bytes(), transfer_derive_sas_bytes_matches_fixed_vector_and_is_salted(), full_transfer_roundtrip_both_sides_agree(), salted_sas_differs_from_saltless_hkdf(), sas_agrees_both_sides_and_detects_mitm(), sas_bytes_match_fixed_vector(), transfer_key_matches_fixed_vector(), derive_sas() (+20 more)

### Community 16 - "Community 16"
Cohesion: 0.07
Nodes (1): IntegrityCheckingUniffiLib

### Community 17 - "Community 17"
Cohesion: 0.1
Nodes (4): plan_monthly_cost_cents(), effective_quota(), monthly_cost_cents(), Plan

### Community 18 - "Community 18"
Cohesion: 0.22
Nodes (22): derive_request_wrap_key(), derive_request_wrap_key_deterministic(), derive_request_wrap_key_varies_by_request_id(), derive_seal_key(), each_seal_uses_a_fresh_ephemeral_key(), full_owner_uploader_pipeline(), open_rejects_low_order_ephemeral_public(), open_rejects_tampered_wrapped_key() (+14 more)

### Community 19 - "Community 19"
Cohesion: 0.2
Nodes (19): ResizeFailed, aspect_ratio_preserved_landscape(), aspect_ratio_preserved_portrait(), encode_webp(), generate_thumbnail(), LadderStep, large_config_produces_output(), make_test_rgba() (+11 more)

### Community 20 - "Community 20"
Cohesion: 0.16
Nodes (14): approx_text_width(), build_content_stream(), generate_recovery_pdf(), pdf_contains_all_six_objects(), pdf_contains_metadata(), pdf_contains_title(), pdf_contains_words(), pdf_empty_words() (+6 more)

### Community 21 - "Community 21"
Cohesion: 0.1
Nodes (21): UniffiInternalError, bufferOverflow, incompleteData, rustPanic, unexpectedEnumCase, unexpectedNullPointer, unexpectedOptionalTag, unexpectedRustCallError (+13 more)

### Community 22 - "Community 22"
Cohesion: 0.27
Nodes (12): diff_manifest(), empty_both_sides_is_noop(), equal_version_is_noop(), local_newer_is_put_remote_newer_is_get(), local_only_is_put(), mixed_authoritative_rebuild(), r(), remote_only_authoritative_is_delete() (+4 more)

### Community 23 - "Community 23"
Cohesion: 0.25
Nodes (12): base_chunk_size(), ChunkPlan, ChunkProfile, ChunkStrategy, div_ceil_u64(), effective_cap(), max_plaintext_chunk_bytes(), next_pow2() (+4 more)

### Community 26 - "Community 26"
Cohesion: 0.27
Nodes (11): derive_sas_bytes(), derive_sas_bytes_deterministic(), derive_sas_bytes_different_info_differ(), derive_sas_bytes_different_secrets_differ(), derive_sas_bytes_matches_transfer_crypto(), derive_sas_bytes_zero_length(), sha256(), sha256_abc() (+3 more)

### Community 36 - "Community 36"
Cohesion: 0.22
Nodes (7): ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode

### Community 43 - "Community 43"
Cohesion: 0.29
Nodes (2): DownloadCallbackBridge, UploadCallbackBridge

### Community 57 - "Community 57"
Cohesion: 0.4
Nodes (1): UploadError

### Community 66 - "Community 66"
Cohesion: 0.5
Nodes (3): PendingOp, SyncOp, TreeNode

### Community 71 - "Community 71"
Cohesion: 0.67
Nodes (2): ChunkMeta, EncryptedBlob

### Community 73 - "Community 73"
Cohesion: 1.0
Nodes (1): WasmChunkEncryptor

### Community 74 - "Community 74"
Cohesion: 1.0
Nodes (1): CoreError

### Community 75 - "Community 75"
Cohesion: 1.0
Nodes (1): SyncEvent

### Community 76 - "Community 76"
Cohesion: 1.0
Nodes (1): SyncError

## Knowledge Gaps
- **176 isolated node(s):** `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag`, `unexpectedEnumCase`, `unexpectedNullPointer` (+171 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 16`** (29 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (8 nodes): `DownloadCallbackBridge`, `.on_chunk_decrypted()`, `.on_complete()`, `.on_error()`, `UploadCallbackBridge`, `.on_chunk_uploaded()`, `.on_complete()`, `.on_error()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 57`** (5 nodes): `error.rs`, `UploadError`, `.fmt()`, `.is_retryable()`, `.retry_after()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 71`** (3 nodes): `file.rs`, `ChunkMeta`, `EncryptedBlob`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 73`** (2 nodes): `beebeeb_wasm.d.ts`, `WasmChunkEncryptor`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 74`** (2 nodes): `error.rs`, `CoreError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 75`** (2 nodes): `events.rs`, `SyncEvent`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 76`** (2 nodes): `error.rs`, `SyncError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ok` connect `Community 2` to `Community 3`, `Community 6`, `Community 7`, `Community 9`, `Community 10`, `Community 12`, `Community 13`, `Community 14`, `Community 15`, `Community 18`, `Community 19`?**
  _High betweenness centrality (0.245) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 2` to `Community 1`?**
  _High betweenness centrality (0.161) - this node is a cross-community bridge._
- **Why does `UniffiLib` connect `Community 0` to `Community 4`?**
  _High betweenness centrality (0.095) - this node is a cross-community bridge._
- **Are the 171 inferred relationships involving `ok` (e.g. with `derive_master_key()` and `derive_file_key()`) actually correct?**
  _`ok` has 171 INFERRED edges - model-reasoned connections that need verification._
- **What connects `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag` to the rest of the system?**
  _176 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._