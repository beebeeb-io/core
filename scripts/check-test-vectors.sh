#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

python3 -c 'import cryptography' || {
  echo "Python package 'cryptography' is required" >&2
  exit 1
}

vector_tmp=$(mktemp -d "${TMPDIR:-/tmp}/beebeeb-vectors.XXXXXX")
trap 'rm -rf "$vector_tmp"' EXIT
cp -R test-vectors "$vector_tmp/test-vectors"

export PYTHONDONTWRITEBYTECODE=1

python3 "$vector_tmp/test-vectors/tools/check_key_proof.py" "$vector_tmp/test-vectors/vectors.json"
python3 "$vector_tmp/test-vectors/tools/check_version_metadata.py" "$vector_tmp/test-vectors/vectors.json"
python3 "$vector_tmp/test-vectors/tools/jitter_port.py"
python3 "$vector_tmp/test-vectors/tools/make_upper_repair_vectors.py" "$vector_tmp/test-vectors/vectors.json"

python3 "$vector_tmp/test-vectors/tools/make_owner_file_key_vector.py" "$vector_tmp/test-vectors/vectors.json"
cmp test-vectors/vectors.json "$vector_tmp/test-vectors/vectors.json"

python3 "$vector_tmp/test-vectors/tools/make_direct_transfer_vectors.py" "$vector_tmp/test-vectors/direct_transfer.json"
cmp test-vectors/direct_transfer.json "$vector_tmp/test-vectors/direct_transfer.json"

python3 "$vector_tmp/test-vectors/tools/make_direct_upload_vectors.py" "$vector_tmp/test-vectors/direct_upload.json"
cmp test-vectors/direct_upload.json "$vector_tmp/test-vectors/direct_upload.json"

python3 "$vector_tmp/test-vectors/tools/make_direct_upload_pipeline_vectors.py"
cmp test-vectors/direct_upload_pipeline.json "$vector_tmp/test-vectors/direct_upload_pipeline.json"

echo "all test-vector Python tools passed; generated files are unchanged"
