#!/usr/bin/env bash
# The committed contract vectors must be exactly what the generator writes, byte for byte.
# The generator is hand-authored from the spec (the rows are not derived from the code), so this
# catches an edit made to the JSON without the generator — the drift that left the K1 file with a
# row and source lines the generator no longer produced.
#   test-vectors/tools/check-direct-vectors-generated.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
committed="$repo/test-vectors/direct_transfer.json"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
python3 -I "$here/make_direct_transfer_vectors.py" "$tmp" >/dev/null
if ! cmp -s "$committed" "$tmp"; then
  echo "direct_transfer.json is not what make_direct_transfer_vectors.py writes:" >&2
  diff -u "$committed" "$tmp" >&2 || true
  exit 1
fi
echo "direct_transfer.json matches its generator"
