#!/usr/bin/env bash
# The committed contract vectors must be exactly what the generator writes, byte for byte.
# The generator is authored from the spec (the rows are not derived from the code), so this
# catches an edit made to the JSON without the generator — the drift that left the K1 file with a
# row and source lines the generator no longer produced.
#   test-vectors/tools/check-direct-vectors-generated.sh [PATH]
#   test-vectors/tools/check-direct-vectors-generated.sh --self-test
# With no PATH, PATH defaults to the committed test-vectors/direct_transfer.json. Any other file is
# checked instead, so the self-test can exercise this very gate on a hand-edited copy.
# `--self-test` proves the gate can go red: it runs the plain gate on the committed file (which must
# accept it), then copies the committed bytes to a TEMP path, changes ONE byte there — the first
# digit of the first `"expected": <n>` it finds, located by regex, never a hard-coded row — and runs
# the plain gate on that copy, which must exit 1. A copy that is accepted (a gate that cannot go
# red), an edit that changed nothing, or any other exit status exits non-zero. CI runs both forms.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
committed="$repo/test-vectors/direct_transfer.json"

usage() { echo "usage: $0 [PATH | --self-test]" >&2; exit 2; }
[ $# -le 1 ] || usage
mode=check
target=$committed
if [ $# -eq 1 ]; then
  case "$1" in
    --self-test) mode=self-test ;;
    -*) usage ;;
    *) target=$1 ;;
  esac
fi

# 0 = $1 differs from what the generator writes (the gate rejects it); 1 = the bytes are identical.
differs() {
  local generated
  generated=$(mktemp)
  python3 -I "$here/make_direct_transfer_vectors.py" "$generated" >/dev/null
  if cmp -s "$1" "$generated"; then
    rm -f "$generated"
    return 1
  fi
  diff -u "$1" "$generated" >&2 || true
  rm -f "$generated"
  return 0
}

if [ "$mode" = "check" ]; then
  if differs "$target"; then
    echo "$target is not what make_direct_transfer_vectors.py writes" >&2
    exit 1
  fi
  echo "$target matches its generator"
  exit 0
fi

# A self-test over a drifted file would prove nothing: the plain gate (the very code the CI step
# runs) must first accept the committed file.
status=0
"$0" "$committed" >/dev/null 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
  echo "self-test: the plain gate rejected the committed file (exit $status) — fix that first" >&2
  exit 1
fi

edited=$(mktemp)
trap 'rm -f "$edited"' EXIT
python3 -I - "$committed" "$edited" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r'("expected":\s*)(\d)', text)
if match is None:
    sys.exit('self-test: no "expected": <n> row to edit')
digit = str((int(match.group(2)) + 1) % 10)
with open(sys.argv[2], "w", encoding="utf-8", newline="") as f:
    f.write(text[: match.start(2)] + digit + text[match.end(2) :])
PY
if cmp -s "$edited" "$committed"; then
  echo "self-test: the edit changed nothing — the self-test proves nothing" >&2
  exit 1
fi

status=0
"$0" "$edited" >/dev/null 2>&1 || status=$?
if [ "$status" -ne 1 ]; then
  echo "self-test: the plain gate on an edited copy exited $status, expected 1 (0 = it cannot go red)" >&2
  exit 1
fi
echo "self-test: the plain gate rejected the edited copy, and accepted the committed file"
