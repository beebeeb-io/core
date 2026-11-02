# Graph Summary - core  (2026-06-25)

> Made from GRAPH_REPORT.md by scripts/graphify-summary.sh. Detail: graphify query "<question>" or graphify explain <symbol>. Never read GRAPH_REPORT.md whole.

## Summary
- 3035 nodes · 7424 edges · 38 communities detected
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 1129 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

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

## Top 20 communities (first symbols)
- Community 0 - "Community 0" | 228 nodes: ArchiveEntryDto, CachedFileEntryData, ChunkDecryptorHandle, ChunkEncryptorHandle, ChunkEncryptorSummaryDto, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode() (+220 more)
- Community 1 - "Community 1" | 221 nodes: ChunkDecryptorHandle, ChunkEncryptorHandle, computeRecoveryCheck(), ConstellationDecoderHandle, constellationEncode(), constellationNewSession(), constellationVerifyCode(), createReader() (+213 more)
- Community 2 - "Community 2" | 312 nodes: Opaque, hex(), main(), ok, edge_pairs(), compare(), confirm_code_verifies(), constellation_new_session() (+304 more)
- Community 3 - "Community 3" | 104 nodes: alloc(), ByReference, ByValue, Cleanable, `computeRecoveryCheck`(), CryptoException, `decryptChunk`(), Decryption (+96 more)
- Community 4 - "Community 4" | 116 nodes: AnyObject, ChunkDecryptorHandleProtocol, ChunkEncryptorHandleProtocol, ChunkPlanResult, ConstellationDecoderHandleProtocol, ConstellationEdgeDto, ConstellationNodeDto, ConstellationPayloadDto (+108 more)
- Community 5 - "Community 5" | 93 nodes: create(), Encryption, FfiConverterTypeCryptoError, Io, decrypt_chunk(), decrypt_chunk_raw(), decrypt_chunks_to_file(), decrypt_chunks_to_file_empty() (+85 more)
- Community 6 - "Community 6" | 58 nodes: InvalidInput, check_explicit_chunk_size(), ChunkDecryptor, ChunkEncryptor, ChunkEncryptorSummary, CountingReader, decrypt_frames(), DecryptedChunk (+50 more)
- Community 7 - "Community 7" | 67 nodes: ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload, ConstellationSessionInit, ObservedEdge, ObservedNode, decrypt_chunk() (+59 more)
- Community 8 - "Community 8" | 1 nodes: UniffiLib
- Community 9 - "Community 9" | 57 nodes: addHeapObject(), compute_recovery_check(), debugString(), decodeText(), decompress_gzip(), decrypt_chunk(), decrypt_chunks(), decrypt_metadata() (+49 more)
- Community 10 - "Community 10" | 33 nodes: InvalidResponse, Network, boundaries_minimum_valid_single_chunk(), boundaries_single_chunk(), boundaries_three_chunks_with_remainder(), boundaries_two_equal_chunks(), compute_chunk_boundaries(), decrypt_downloaded_bytes() (+25 more)
- Community 11 - "Community 11" | 37 nodes: bucket_is_deterministic_and_bounded(), bucket_of(), BucketData, delete_touches_only_affected_shards_and_removes(), encrypt_decrypt_roundtrip_preserves_queries(), EncryptedShard, est_file(), est_posting() (+29 more)
- Community 12 - "Community 12" | 26 nodes: clean_roundtrip_one_frame_per_shard(), ConstellationDecoder, DecoderState, dummy_payload(), first_eight_shards_are_enough(), frame_to_observations(), missing_observations_skip_the_frame(), parity_shards_can_substitute_for_data_shards() (+18 more)
- Community 13 - "Community 13" | 13 nodes: op(), string_field(), SyncEngine, test_apply_remote_file_create(), test_apply_remote_file_move(), test_apply_remote_file_rename(), test_echo_suppression(), test_permanent_delete_clears_pin() (+5 more)
- Community 14 - "Community 14" | 31 nodes: Kdf, derive_file_key(), derive_file_key_deterministic(), derive_master_key(), derive_master_key_deterministic(), derive_master_key_produces_32_bytes(), derive_search_index_key(), different_file_ids_yield_different_keys() (+23 more)
- Community 15 - "Community 15" | 26 nodes: aes_gcm_decrypt(), bad_nonce_length_is_rejected(), both_sides_derive_the_same_shared_secret(), browser_encrypt(), CliEphemeralKey, decrypt_cli_payload(), derive_cli_auth_key(), derive_cli_auth_key_varies_by_secret() (+18 more)
- Community 16 - "Community 16" | 25 nodes: full_transfer_roundtrip_both_sides_agree(), salted_sas_differs_from_saltless_hkdf(), sas_agrees_both_sides_and_detects_mitm(), sas_bytes_match_fixed_vector(), transfer_key_matches_fixed_vector(), derive_sas(), derive_shared_secret() ...
- Community 17 - "Community 17" | 5 nodes: plan_effective_quota(), plan_monthly_cost_cents(), effective_quota(), monthly_cost_cents(), Plan
- Community 18 - "Community 18" | 22 nodes: derive_request_wrap_key(), derive_request_wrap_key_deterministic(), derive_request_wrap_key_varies_by_request_id(), derive_seal_key(), each_seal_uses_a_fresh_ephemeral_key(), full_owner_uploader_pipeline(), open_rejects_low_order_ephemeral_public() ...
- Community 19 - "Community 19" | 19 nodes: ResizeFailed, aspect_ratio_preserved_landscape(), aspect_ratio_preserved_portrait(), encode_webp(), generate_thumbnail(), LadderStep, large_config_produces_output(), make_test_rgba() (+11 more)
