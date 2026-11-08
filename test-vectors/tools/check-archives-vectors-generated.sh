#!/usr/bin/env bash
# The committed archive vectors must be exactly what their generator writes, byte for byte:
# test-vectors/archives_v1.json and every fixture gen_archives_v1.py makes in test-vectors/archives/.
# (The password fixtures come from 7-Zip and Info-ZIP, make_archive_password_fixtures.sh, salted at
# random; the Rust runner checks that each has a row.) The generator is written from the spec, never
# from the Rust it tests, so this catches a hand edit to the JSON or to a generated fixture.
#   test-vectors/tools/check-archives-vectors-generated.sh                check the committed files
#   test-vectors/tools/check-archives-vectors-generated.sh JSON DIR       check JSON and the fixtures in DIR
#   test-vectors/tools/check-archives-vectors-generated.sh --self-test    prove the gate can go red
# `--self-test` first runs the plain gate (it must accept the committed files), then checks two
# edited TEMP copies, each of which must exit 1: the JSON with ONE byte changed (the first letter
# of the first display path, located by regex, never a hard-coded row), and the fixture directory
# with ONE byte of a generated fixture changed. An edited copy that is accepted (a gate that cannot
# go red), an edit that changed nothing, or any other exit status exits non-zero. CI runs both forms.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
committed_json="$repo/test-vectors/archives_v1.json"
committed_dir="$repo/test-vectors/archives"

usage() { echo "usage: $0 [JSON DIR | --self-test]" >&2; exit 2; }

# Exit 0 when JSON ($1) and every generated fixture in DIR ($2) match the generator; 1 otherwise.
check() {
  local work failed=0 name
  work=$(mktemp -d)
  python3 -I "$here/gen_archives_v1.py" "$work/archives_v1.json" "$work/archives" >/dev/null
  if ! cmp -s "$1" "$work/archives_v1.json"; then
    diff -u "$1" "$work/archives_v1.json" >&2 || true
    echo "$1 is not what gen_archives_v1.py writes" >&2
    failed=1
  fi
  for generated in "$work/archives"/*; do
    name=$(basename "$generated")
    if ! cmp -s "$2/$name" "$generated"; then
      echo "$2/$name is not what gen_archives_v1.py writes" >&2
      failed=1
    fi
  done
  if [ "$failed" -eq 0 ]; then
    python3 -I - "$1" "$work/archives" <<'PY'
import json, os, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"archives_v1.json matches gen_archives_v1.py: {len(doc['fixtures'])} fixtures "
      f"({len(os.listdir(sys.argv[2]))} generated, byte-equal), {len(doc['words'])} words, "
      f"{len(doc['counts'])} counts, {len(doc['sizes'])} sizes")
PY
  fi
  rm -rf "$work"
  return "$failed"
}

case $# in
  0) check "$committed_json" "$committed_dir"; exit $? ;;
  1) [ "$1" = "--self-test" ] || usage ;;
  2) check "$1" "$2"; exit $? ;;
  *) usage ;;
esac

# --self-test. A self-test over drifted files would prove nothing: the plain gate (the very code
# the CI step runs) must first accept the committed files.
status=0
"$0" >/dev/null 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
  echo "self-test: the plain gate rejected the committed files (exit $status) — fix that first" >&2
  exit 1
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
python3 -I - "$committed_json" "$scratch/edited.json" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r'("display_path":\s*")([a-z])', text)
if match is None:
    sys.exit('self-test: no "display_path": "<letter>... row to edit')
letter = chr((ord(match.group(2)) - ord("a") + 1) % 26 + ord("a"))
with open(sys.argv[2], "w", encoding="utf-8", newline="") as f:
    f.write(text[: match.start(2)] + letter + text[match.end(2) :])
PY
if cmp -s "$scratch/edited.json" "$committed_json"; then
  echo "self-test: the edit of archives_v1.json changed nothing — the self-test proves nothing" >&2
  exit 1
fi
status=0
"$0" "$scratch/edited.json" "$committed_dir" >/dev/null 2>&1 || status=$?
if [ "$status" -ne 1 ]; then
  echo "self-test: the gate on an edited archives_v1.json exited $status, expected 1 (0 = it cannot go red)" >&2
  exit 1
fi

cp -R "$committed_dir" "$scratch/archives"
python3 -I - "$scratch/archives/plain.zip" <<'PY'
import sys

data = bytearray(open(sys.argv[1], "rb").read())
data[len(data) // 2] ^= 0x01
open(sys.argv[1], "wb").write(bytes(data))
PY
if cmp -s "$scratch/archives/plain.zip" "$committed_dir/plain.zip"; then
  echo "self-test: the edit of plain.zip changed nothing — the self-test proves nothing" >&2
  exit 1
fi
status=0
"$0" "$committed_json" "$scratch/archives" >/dev/null 2>&1 || status=$?
if [ "$status" -ne 1 ]; then
  echo "self-test: the gate on an edited plain.zip exited $status, expected 1 (0 = it cannot go red)" >&2
  exit 1
fi
echo "self-test: the plain gate rejected an edited archives_v1.json and an edited plain.zip, and accepted the committed files"
