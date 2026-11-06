#!/usr/bin/env bash
# The committed backup vectors (LD-0113) must be exactly what their generators write, byte for
# byte: test-vectors/consolidation/backup_{protect,device,root,plan}.json from
# test-vectors/tools/make_backup_{protect,device,root,plan}_vectors.py. The generators are written
# from the spec, never from the Rust they test, so this catches a hand edit to the JSON.
#   test-vectors/tools/check-backup-vectors-generated.sh                 check all four committed files
#   test-vectors/tools/check-backup-vectors-generated.sh NAME PATH       check PATH against NAME's generator
#   test-vectors/tools/check-backup-vectors-generated.sh --self-test     prove the gate can go red
# NAME is protect, device, root or plan. `--self-test` first runs the plain gate on the committed
# files (it must accept them), then, for each of the four, copies the committed bytes to a TEMP
# path, changes ONE byte there (the first letter of the first case id, located by regex, never a
# hard-coded row) and runs the plain gate on that copy, which must exit 1. A copy that is accepted
# (a gate that cannot go red), an edit that changed nothing, or any other exit status exits
# non-zero. CI runs both forms.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
names="protect device root plan"

usage() { echo "usage: $0 [NAME PATH | --self-test]" >&2; exit 2; }

committed() { echo "$repo/test-vectors/consolidation/backup_$1.json"; }

# 0 = $2 differs from what NAME's generator writes (the gate rejects it); 1 = identical.
differs() {
  local generated
  generated=$(mktemp)
  python3 -I "$here/make_backup_$1_vectors.py" "$generated" >/dev/null
  if cmp -s "$2" "$generated"; then
    rm -f "$generated"
    return 1
  fi
  diff -u "$2" "$generated" >&2 || true
  rm -f "$generated"
  return 0
}

check_one() {
  if differs "$1" "$2"; then
    echo "$2 is not what make_backup_$1_vectors.py writes" >&2
    return 1
  fi
  echo "$2 matches its generator"
}

case $# in
  0)
    failed=0
    for name in $names; do
      check_one "$name" "$(committed "$name")" || failed=1
    done
    exit "$failed"
    ;;
  1)
    [ "$1" = "--self-test" ] || usage
    ;;
  2)
    case " $names " in *" $1 "*) ;; *) usage ;; esac
    check_one "$1" "$2"
    exit $?
    ;;
  *) usage ;;
esac

# --self-test. A self-test over drifted files would prove nothing: the plain gate (the very code
# the CI step runs) must first accept the committed files.
status=0
"$0" >/dev/null 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
  echo "self-test: the plain gate rejected a committed file (exit $status) — fix that first" >&2
  exit 1
fi

edited=$(mktemp)
trap 'rm -f "$edited"' EXIT
for name in $names; do
  python3 -I - "$(committed "$name")" "$edited" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r'("id":\s*")([a-z])', text)
if match is None:
    sys.exit('self-test: no "id": "<letter>... case to edit')
letter = chr((ord(match.group(2)) - ord("a") + 1) % 26 + ord("a"))
with open(sys.argv[2], "w", encoding="utf-8", newline="") as f:
    f.write(text[: match.start(2)] + letter + text[match.end(2) :])
PY
  if cmp -s "$edited" "$(committed "$name")"; then
    echo "self-test: the edit of backup_$name.json changed nothing — the self-test proves nothing" >&2
    exit 1
  fi
  status=0
  "$0" "$name" "$edited" >/dev/null 2>&1 || status=$?
  if [ "$status" -ne 1 ]; then
    echo "self-test: the gate on an edited backup_$name.json exited $status, expected 1 (0 = it cannot go red)" >&2
    exit 1
  fi
done
echo "self-test: the plain gate rejected an edited copy of each of the 4 files, and accepted the committed files"
