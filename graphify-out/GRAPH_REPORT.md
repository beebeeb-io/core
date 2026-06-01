# Graph Report - core  (2026-06-01)

## Corpus Check
- 113 files · ~212,175 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2828 nodes · 6737 edges · 38 communities detected
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 935 edges (avg confidence: 0.8)
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
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]

## God Nodes (most connected - your core abstractions)
1. `ok` - 149 edges
2. `UniffiLib` - 85 edges
3. `rustCallWithError()` - 75 edges
4. `rustCallWithError()` - 75 edges
5. `derive_master_key()` - 62 edges
6. `FfiConverterRustBuffer` - 50 edges
7. `FfiConverterRustBuffer` - 50 edges
8. `readInt()` - 40 edges
9. `readInt()` - 40 edges
10. `writeInt()` - 39 edges

## Surprising Connections (you probably didn't know these)
- `plan_chunks()` --calls--> `n32_ladder_vectors_hold_for_backup_profile()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-types/tests/chunk_planning.rs
- `plan_chunks()` --calls--> `zero_and_one_byte_are_single_4mib_chunks()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-types/tests/chunk_planning.rs
- `plan_chunks()` --calls--> `static_caps_per_profile()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-types/tests/chunk_planning.rs
- `row_to_entry()` --calls--> `ok`  [INFERRED]
  beebeeb-core/src/fp_cache.rs → beebeeb-uniffi/bindings/beebeeb_uniffi.swift
- `derive_master_key()` --calls--> `file_encrypt_matches_direct_chunk_encryptor_loop()`  [INFERRED]
  beebeeb-uniffi/src/lib.rs → beebeeb-core/tests/chunk_stream_parity.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (223): ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode(), createReader() (+215 more)

### Community 1 - "Community 1"
Cohesion: 0.02
Nodes (277): Opaque, hex(), main(), ok, config_new_sets_defaults(), config_roundtrips_through_json(), SyncConfig, SyncMode (+269 more)

### Community 2 - "Community 2"
Cohesion: 0.01
Nodes (165): UniffiLib, ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode() (+157 more)

### Community 3 - "Community 3"
Cohesion: 0.01
Nodes (104): alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), CryptoException, `decryptChunk`(), Decryption (+96 more)

### Community 4 - "Community 4"
Cohesion: 0.02
Nodes (121): AnyObject, ArchiveEntryDto, CachedFileEntryData, ChunkDecryptorHandleProtocol, ChunkEncryptorHandleProtocol, ChunkEncryptorSummaryDto, ChunkPlanResult, ConstellationDecoderHandleProtocol (+113 more)

### Community 5 - "Community 5"
Cohesion: 0.02
Nodes (62): createReader(), createWriter(), Data, FfiConverterData, FfiConverterOptionCallbackInterfaceDownloadProgressCallback, FfiConverterOptionCallbackInterfaceFileProgressCallback, FfiConverterOptionCallbackInterfaceUploadProgressCallback, FfiConverterOptionString (+54 more)

### Community 6 - "Community 6"
Cohesion: 0.04
Nodes (64): InvalidResponse, Network, boundaries_minimum_valid_single_chunk(), boundaries_single_chunk(), boundaries_three_chunks_with_remainder(), boundaries_two_equal_chunks(), compute_chunk_boundaries(), decrypt_downloaded_bytes() (+56 more)

### Community 7 - "Community 7"
Cohesion: 0.07
Nodes (71): create(), Encryption, decrypt_blob(), empty_plaintext_roundtrip(), encrypt_blob(), large_payload(), roundtrip(), tampered_ciphertext_fails() (+63 more)

### Community 8 - "Community 8"
Cohesion: 0.08
Nodes (44): InvalidInput, ChunkDecryptor, ChunkEncryptor, ChunkEncryptorSummary, CountingReader, decrypt_frames(), DecryptedChunk, decryptor_chunk_size_zero_errors() (+36 more)

### Community 9 - "Community 9"
Cohesion: 0.1
Nodes (56): addHeapObject(), compute_recovery_check(), debugString(), decodeText(), decompress_gzip(), decrypt_chunk(), decrypt_chunks(), decrypt_metadata() (+48 more)

### Community 10 - "Community 10"
Cohesion: 0.11
Nodes (34): Io, ArchiveEntry, build_tar(), decompress_gzip(), gzip_invalid_data(), gzip_roundtrip(), list_archive(), list_archive_plain_gz() (+26 more)

### Community 11 - "Community 11"
Cohesion: 0.1
Nodes (24): clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+16 more)

### Community 12 - "Community 12"
Cohesion: 0.12
Nodes (13): op(), string_field(), SyncEngine, test_apply_remote_file_create(), test_apply_remote_file_move(), test_apply_remote_file_rename(), test_echo_suppression(), test_permanent_delete_clears_pin() (+5 more)

### Community 13 - "Community 13"
Cohesion: 0.12
Nodes (24): Kdf, derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), different_file_ids_yield_different_keys(), different_passwords_yield_different_keys() (+16 more)

### Community 14 - "Community 14"
Cohesion: 0.07
Nodes (1): IntegrityCheckingUniffiLib

### Community 15 - "Community 15"
Cohesion: 0.1
Nodes (4): storage_format_si(), effective_quota(), format_storage_si(), Plan

### Community 16 - "Community 16"
Cohesion: 0.15
Nodes (14): approx_text_width(), build_content_stream(), generate_recovery_pdf(), pdf_contains_all_six_objects(), pdf_contains_metadata(), pdf_contains_title(), pdf_contains_words(), pdf_empty_words() (+6 more)

### Community 17 - "Community 17"
Cohesion: 0.2
Nodes (19): ResizeFailed, aspect_ratio_preserved_landscape(), aspect_ratio_preserved_portrait(), encode_webp(), generate_thumbnail(), LadderStep, large_config_produces_output(), make_test_rgba() (+11 more)

### Community 18 - "Community 18"
Cohesion: 0.17
Nodes (15): BitArray, constellation_encode(), dummy_payload(), encode_shards(), frame_brightness_quantises_to_known_levels(), mix64(), pack_shard(), pack_shard_uses_full_capacity() (+7 more)

### Community 19 - "Community 19"
Cohesion: 0.1
Nodes (20): UniffiInternalError, bufferOverflow, incompleteData, rustPanic, unexpectedEnumCase, unexpectedNullPointer, unexpectedOptionalTag, unexpectedRustCallError (+12 more)

### Community 20 - "Community 20"
Cohesion: 0.19
Nodes (12): derive_sas(), derive_shared_secret(), derive_transfer_key(), derive_transfer_key_is_deterministic(), fresh_keypairs_yield_different_shared_secrets(), key_exchange_roundtrip_yields_same_shared_secret(), sas_is_deterministic(), sas_to_words() (+4 more)

### Community 21 - "Community 21"
Cohesion: 0.31
Nodes (13): bundle_files(), empty_bundle_roundtrip(), empty_file_roundtrip(), header_with_huge_count_does_not_oom(), invalid_utf8_filename_returns_error(), read_slice(), read_u32(), read_u64() (+5 more)

### Community 22 - "Community 22"
Cohesion: 0.25
Nodes (12): base_chunk_size(), ChunkPlan, ChunkProfile, ChunkStrategy, div_ceil_u64(), effective_cap(), max_plaintext_chunk_bytes(), next_pow2() (+4 more)

### Community 25 - "Community 25"
Cohesion: 0.27
Nodes (11): derive_sas_bytes(), derive_sas_bytes_deterministic(), derive_sas_bytes_different_info_differ(), derive_sas_bytes_different_secrets_differ(), derive_sas_bytes_matches_transfer_crypto(), derive_sas_bytes_zero_length(), sha256(), sha256_abc() (+3 more)

### Community 26 - "Community 26"
Cohesion: 0.29
Nodes (11): conflict_without_prior_sync_when_timestamps_differ(), ConflictResolution, detect_conflicts(), detects_conflict_when_both_sides_changed(), FileMeta, loser_filename(), loser_filename_includes_device_and_time(), loser_filename_works_without_extension() (+3 more)

### Community 36 - "Community 36"
Cohesion: 0.22
Nodes (7): ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode

### Community 43 - "Community 43"
Cohesion: 0.25
Nodes (3): n32_ladder_vectors_hold_for_backup_profile(), static_caps_per_profile(), zero_and_one_byte_are_single_4mib_chunks()

### Community 56 - "Community 56"
Cohesion: 0.6
Nodes (2): envelope_round_trip(), OpaqueEnvelope

### Community 58 - "Community 58"
Cohesion: 0.4
Nodes (1): UploadError

### Community 66 - "Community 66"
Cohesion: 0.5
Nodes (2): ZipEntry, ZipProgress

### Community 68 - "Community 68"
Cohesion: 0.5
Nodes (3): PendingOp, SyncOp, TreeNode

### Community 69 - "Community 69"
Cohesion: 0.5
Nodes (1): blake3_hash()

### Community 70 - "Community 70"
Cohesion: 0.5
Nodes (3): CipherSuite, KdfAlgorithm, KdfParams

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
- **158 isolated node(s):** `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag`, `unexpectedEnumCase`, `unexpectedNullPointer` (+153 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 14`** (29 nodes): `IntegrityCheckingUniffiLib`, `.ffi_beebeeb_uniffi_uniffi_contract_version()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_keychain_bytes()`, `.uniffi_beebeeb_uniffi_checksum_constructor_masterkeyhandle_from_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_master_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_share_key()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_func_derive_x25519_public()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_func_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_func_generate_recovery_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_login_start()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_finish()`, `.uniffi_beebeeb_uniffi_checksum_func_opaque_registration_start()`, `.uniffi_beebeeb_uniffi_checksum_func_recover_from_phrase()`, `.uniffi_beebeeb_uniffi_checksum_func_x25519_shared_secret()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_decrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_chunk()`, `.uniffi_beebeeb_uniffi_checksum_method_filekeyhandle_encrypt_metadata()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_compute_recovery_check()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_file_key()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_derive_x25519_private()`, `.uniffi_beebeeb_uniffi_checksum_method_masterkeyhandle_export_for_keychain()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 56`** (5 nodes): `envelope_round_trip()`, `OpaqueEnvelope`, `.from_bytes()`, `.into_master_key()`, `.to_bytes()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 58`** (5 nodes): `error.rs`, `UploadError`, `.fmt()`, `.is_retryable()`, `.retry_after()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 66`** (4 nodes): `zip.rs`, `estimate_zip_size()`, `ZipEntry`, `ZipProgress`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 69`** (4 nodes): `hash.rs`, `blake3_hash()`, `deterministic()`, `empty_input_has_known_hash()`
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

- **Why does `ok` connect `Community 1` to `Community 0`, `Community 6`, `Community 7`, `Community 8`, `Community 10`, `Community 11`, `Community 13`, `Community 17`, `Community 21`?**
  _High betweenness centrality (0.218) - this node is a cross-community bridge._
- **Why does `InitializationResult` connect `Community 0` to `Community 1`?**
  _High betweenness centrality (0.153) - this node is a cross-community bridge._
- **Why does `UniffiLib` connect `Community 2` to `Community 0`, `Community 3`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Are the 148 inferred relationships involving `ok` (e.g. with `derive_master_key()` and `derive_file_key()`) actually correct?**
  _`ok` has 148 INFERRED edges - model-reasoned connections that need verification._
- **What connects `bufferOverflow`, `incompleteData`, `unexpectedOptionalTag` to the rest of the system?**
  _158 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.02 - nodes in this community are weakly interconnected._