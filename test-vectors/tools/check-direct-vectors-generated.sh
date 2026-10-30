#!/usr/bin/env bash
# The committed contract vectors must be exactly what the generator writes, byte for byte.
# The generator is authored from the spec (the rows are not derived from the code), so this
# catches an edit made to the JSON without the generator — the drift that left the K1 file with a
# row and source lines the generator no longer produced.
#   test-vectors/tools/check-direct-vectors-generated.sh
#   test-vectors/tools/check-direct-vectors-generated.sh --self-test
# `--self-test` proves the check can go red: it edits a TEMP COPY of the committed bytes (never the
# committed file) so the ONLY difference is one field, then runs the same comparison. It exits 0
# ONLY when that edited copy was REJECTED; an accepted copy (a check that cannot go red) or an edit
# that changed nothing exits non-zero. CI runs the plain form and the self-test as plain steps.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
committed="$repo/test-vectors/direct_transfer.json"
mode=${1:-check}
if [ "$mode" != "check" ] && [ "$mode" != "--self-test" ]; then
  echo "usage: $0 [--self-test]" >&2
  exit 2
fi
generated=$(mktemp)
edited=""
trap 'rm -f "$generated" $edited' EXIT
python3 -I "$here/make_direct_transfer_vectors.py" "$generated" >/dev/null

# 0 = the check REJECTS $1 (it differs from what the generator writes); 1 = it accepts it.
rejects() {
  if cmp -s "$1" "$generated"; then
    return 1
  fi
  diff -u "$1" "$generated" >&2 || true
  return 0
}

# The committed file must match its generator, in both modes: a self-test over a drifted file
# would prove nothing.
if rejects "$committed"; then
  echo "direct_transfer.json is not what make_direct_transfer_vectors.py writes" >&2
  exit 1
fi
if [ "$mode" = "check" ]; then
  echo "direct_transfer.json matches its generator"
  exit 0
fi

# One edit the generator would never write (`expected` without a matching `content_length`),
# applied to the COMMITTED BYTES, so no re-serialisation can differ for its own reasons.
edited=$(mktemp)
python3 -I - "$committed" "$edited" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
anchor = '"name": "pushes that add up to the grant are the chunk"'
at = text.index(anchor)
head, tail = text[:at], text[at:]
old = '"expected": 4194332'
field = tail.index(old)
with open(sys.argv[2], "w", encoding="utf-8", newline="") as f:
    f.write(head + tail[:field] + '"expected": 4194333' + tail[field + len(old):])
PY
if cmp -s "$edited" "$committed"; then
  echo "self-test: the edit changed nothing — the self-test proves nothing" >&2
  exit 1
fi
if ! rejects "$edited"; then
  echo "self-test: the edited copy was accepted — the check cannot go red" >&2
  exit 1
fi
echo "self-test: the edited copy was rejected, as it must be"
