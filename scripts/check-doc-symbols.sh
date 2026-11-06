#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

must_exist() {
  local file=$1
  local symbol=$2
  if ! rg -q --fixed-strings "$symbol" "$file"; then
    echo "documented code name not found: $symbol ($file)" >&2
    exit 1
  fi
}

for symbol in \
  'ChunkFormat::V1Legacy' 'ExpectedChunkFormat::Unrecorded' 'resume_policy' \
  'WRITE_FORMAT' 'VersionCommitment' 'pub fn with_format' \
  'production_write_format_is_v2' 'p1b_write_switch_uses_v2_and_purpose_subkeys'; do
  must_exist beebeeb-core/src/chunk_stream.rs "$symbol"
done

must_exist beebeeb-core/src/key_proof.rs 'KeyProofVerifier'

for symbol in \
  'METADATA_SEAL_WRITE' 'MetadataSeal::Subkey' 'decrypt_file_metadata' \
  'decrypt_file_metadata_with_key' 'decrypt_name_metadata' 'decrypt_thumbnail' \
  'decrypt_note' 'decrypt_chunks_to_file' 'decrypt_contiguous_to_file'; do
  must_exist beebeeb-core/src/encrypt.rs "$symbol"
done

for symbol in \
  'OwnerKeyConvention::Binary' 'OwnerKeyConvention::UpperRepair' 'open_legacy_child_key' \
  'verify_legacy_folder_key' 'open_legacy_invite_owner_copy'; do
  must_exist beebeeb-core/src/kdf.rs "$symbol"
done

for symbol in \
  'client_login_finish_legacy_upgrade' 'MIN_KSF_VERSION' 'CURRENT_KSF_VERSION'; do
  must_exist beebeeb-core/src/opaque_protocol.rs "$symbol"
done

for symbol in \
  'MasterKeyResult' 'RecoveryPhraseResult' 'OpaqueLoginFinishResult' 'derive_file_key' \
  'recover_from_phrase' 'derive_x25519_private' 'x25519_shared_secret' 'derive_share_key' \
  'derive_request_wrap_key' 'unwrap_request_private' 'open_request_upload' \
  'transfer_derive_key' 'export_for_keychain'; do
  must_exist beebeeb-uniffi/src/lib.rs "$symbol"
done

for symbol in \
  'derive_master_key' 'derive_file_key' 'recover_from_phrase' 'opaque_login_finish' \
  'derive_x25519_private' 'x25519_shared_secret' 'derive_share_key' \
  'derive_request_wrap_key' 'unwrap_request_private' 'open_request_upload' \
  'transfer_derive_key' 'ownerFileKeyForName' 'ownerFileKeyForContent' 'unwrapFolderChild' \
  'unwrapOwnerFileKey' 'openLegacyInviteOwnerCopy' 'unwrapInviteOwnerCopy' \
  'unwrapFolderCustody' 'unwrapLinkOwnerKey' 'openLegacyChildKey'; do
  must_exist beebeeb-wasm/src/lib.rs "$symbol"
done

must_exist beebeeb-uniffi/src/request_seal.rs 'RequestContentReader'
must_exist beebeeb-wasm/src/request_row_exports.rs 'WasmRequestContentReader'
must_exist beebeeb-core/src/file_encrypt.rs 'pub fn decrypt_chunks_to_file'

if rg -q '\bpassword_hash\b' beebeeb-core beebeeb-api beebeeb-store beebeeb-uniffi beebeeb-wasm --glob '*.rs'; then
  echo 'legacy password_hash dual-state code now exists but is not inventoried' >&2
  exit 1
fi

echo 'documented code names match the current Rust sources'
