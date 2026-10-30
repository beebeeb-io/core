#!/usr/bin/env bash
# The committed contract vectors must be exactly what the generator writes, byte for byte.
# The generator is hand-authored from the spec (the rows are not derived from the code), so this
# catches an edit made to the JSON without the generator — the drift that left the K1 file with a
# row and source lines the generator no longer produced.
#   test-vectors/tools/check-direct-vectors-generated.sh
#   test-vectors/tools/check-direct-vectors-generated.sh --self-test
# `--self-test` proves the check can go red: it edits a TEMP COPY (never the committed file) and
# then runs the same comparison, which must exit 1. CI runs the plain form and asserts that the
# self-test form FAILS (`if ... --self-test; then exit 1; fi`).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
committed="$repo/test-vectors/direct_transfer.json"
mode=${1:-check}
if [ "$mode" != "check" ] && [ "$mode" != "--self-test" ]; then
  echo "usage: $0 [--self-test]" >&2
  exit 2
fi
subject="$committed"
if [ "$mode" = "--self-test" ]; then
  # One edit the generator would never write, in the storage_body section: +1 byte on row 1.
  subject=$(mktemp)
  trap 'rm -f "$subject"' EXIT
  python3 -I - "$committed" "$subject" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1], encoding="utf-8"))
assert rows["storage_body"], "the self-test needs a storage_body row to edit"
rows["storage_body"][0]["expected"] += 1
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump(rows, f)
PY
  label="self-test (an edited copy):"
else
  label=""
fi
tmp=$(mktemp)
if [ "$mode" = "--self-test" ]; then
  trap 'rm -f "$tmp" "$subject"' EXIT
else
  trap 'rm -f "$tmp"' EXIT
fi
python3 -I "$here/make_direct_transfer_vectors.py" "$tmp" >/dev/null
if ! cmp -s "$subject" "$tmp"; then
  echo "${label:-}direct_transfer.json is not what make_direct_transfer_vectors.py writes:" >&2
  diff -u "$subject" "$tmp" >&2 || true
  exit 1
fi
if [ "$mode" = "--self-test" ]; then
  echo "self-test: the edited copy was accepted — the check cannot go red" >&2
  exit 1
fi
echo "direct_transfer.json matches its generator"
