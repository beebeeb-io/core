#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

require_fixed() {
  local pattern=$1
  local file=$2
  if ! rg -q --fixed-strings "$pattern" "$file"; then
    echo "legacy-write guard missing in $file: $pattern" >&2
    exit 1
  fi
}

require_fixed 'pub const WRITE_FORMAT: ChunkFormat = ChunkFormat::V2;' beebeeb-core/src/chunk_stream.rs
require_fixed 'const _: () = assert!(matches!(WRITE_FORMAT, ChunkFormat::V2));' beebeeb-core/src/chunk_stream.rs
require_fixed 'pub const METADATA_SEAL_WRITE: MetadataSeal = metadata_seal_for(crate::chunk_stream::WRITE_FORMAT);' beebeeb-core/src/encrypt.rs
require_fixed '#[cfg(any(test, feature = "test-support"))]' beebeeb-core/src/chunk_stream.rs
require_fixed 'pub fn with_format(mut self, format: ChunkFormat)' beebeeb-core/src/chunk_stream.rs
require_fixed 'pub const MIN_KSF_VERSION: u32 = 1;' beebeeb-core/src/opaque_protocol.rs
require_fixed 'pub const CURRENT_KSF_VERSION: u32 = 1;' beebeeb-core/src/opaque_protocol.rs

if ! rg -U -q '#\[cfg\(any\(test, feature = "test-support"\)\)\]\n    pub fn with_format' beebeeb-core/src/chunk_stream.rs; then
  echo 'ChunkEncryptor::with_format is no longer immediately test-gated' >&2
  exit 1
fi

echo 'legacy-write guards: production writes v2 with purpose subkeys; v1 override is test-only'
