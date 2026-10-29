#!/usr/bin/env bash
# canon-sweep — the CLAIM_SWEEP from docs/canon/public-claims.md, run over the
# WHOLE tree of this repo (not only the user-facing paths claims-guard.sh
# scans). It exists because core's design/hifi/ mockups carried "audited by
# Cure53", "audited 2025-09" and "DORA" for months: design/ is outside
# claims-guard.sh's USER_FACING_PATHS, so nothing looked there.
#
#   canon-sweep.sh              scan the repo this script lives in; exit 1 on any row
#   canon-sweep.sh --self-test  prove the sweep can go red on a throwaway copy
#
# Exit 0 clean · 1 violations · 2 misconfiguration.
# The exclusions are the canon's, verbatim: test files and this vendored guard
# dir (a guard quoting a banned phrase in its own regex is not a claim).
# There is no allow-list and no env override — the canon says a new exception
# goes in public-claims.md first, then here, in a reviewed diff.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Canon regex, verbatim from docs/canon/public-claims.md (CLAIM_SWEEP).
CANON_RE='audited (Rust|core|by)|DORA|compliant by architecture|audited 20[0-9]{2}'
CANON_EXCLUDES=(':(exclude)tests/*' ':(exclude,glob)**/*.spec.*' ':(exclude)e2e/*' ':(exclude)scripts/claims-guard/*')

sweep() { # sweep <repo-root> — prints rows, returns 0 clean / 1 rows / 2 error
  local root="$1" out rc
  # --untracked so a freshly written, not-yet-added file is caught by the
  # local run too; CI checks out a clean tree, where it makes no difference.
  out="$(git -C "$root" grep --untracked -nIE -e "$CANON_RE" -- . "${CANON_EXCLUDES[@]}" 2>&1)"
  rc=$?
  if [ "$rc" -gt 1 ]; then echo "canon-sweep: git grep failed (exit $rc): $out" >&2; return 2; fi
  if [ "$rc" -eq 0 ]; then printf '%s\n' "$out"; return 1; fi
  return 0
}

self_test() {
  local tmp rows rc
  tmp="$(mktemp -d)" || exit 2
  trap 'rm -rf "$tmp"' RETURN
  git -C "$tmp" init -q || exit 2
  # 1. A clean tree must pass.
  printf 'Open source, not yet externally audited.\n' > "$tmp/README.md"
  git -C "$tmp" add -A
  sweep "$tmp" >/dev/null; rc=$?
  [ "$rc" -eq 0 ] || { echo "canon-sweep self-test: FAIL — clean tree reported rc=$rc" >&2; exit 1; }
  # 2. Each banned form re-added anywhere — including design/ — must go red.
  local s
  for s in "stat: 'AGPL-3.0 · audited by Cure53'" 'v1.4.2 · audited 2025-09' \
           'one audited core in Rust' 'Built for NIS2 & DORA' 'compliant by architecture'; do
    mkdir -p "$tmp/design/hifi"
    printf '%s\n' "$s" > "$tmp/design/hifi/mock.jsx"
    rows="$(sweep "$tmp")"; rc=$?
    [ "$rc" -eq 1 ] && [ -n "$rows" ] || { echo "canon-sweep self-test: FAIL — did not catch: $s (rc=$rc)" >&2; exit 1; }
    rm -f "$tmp/design/hifi/mock.jsx"
  done
  # 3. The canon exclusions must still apply (a test quoting the regex is not a claim).
  mkdir -p "$tmp/tests"; printf 'audited by Cure53\n' > "$tmp/tests/claims.rs"
  sweep "$tmp" >/dev/null; rc=$?
  [ "$rc" -eq 0 ] || { echo "canon-sweep self-test: FAIL — tests/ exclusion not honoured (rc=$rc)" >&2; exit 1; }
  echo "canon-sweep self-test: 7 of 7 cases behaved (1 clean pass, 5 red, 1 excluded)"
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi

ROOT="$(git -C "$HERE" rev-parse --show-toplevel)" || { echo "canon-sweep: not a git repo" >&2; exit 2; }
echo "canon-sweep: scanning $ROOT"
rows="$(sweep "$ROOT")"; rc=$?
if [ "$rc" -eq 2 ]; then exit 2; fi
if [ "$rc" -eq 1 ]; then
  printf '%s\n' "$rows"
  echo "canon-sweep: FAILED — $(printf '%s\n' "$rows" | wc -l | tr -d ' ') row(s); docs/canon/public-claims.md requires 0" >&2
  exit 1
fi
echo "canon-sweep: clean (0 rows)"
