#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

pin_tokens=$(
  rg -o --no-filename '\b([A-Z][A-Z0-9_]*_)?CORE_REV\b' . \
    --hidden \
    -g '!docs/client-rules.md' \
    -g '!scripts/check-core-pins-documented.sh' \
    -g '!target/**' \
    -g '!graphify-out/**' \
    | sort -u
)

if [[ -z "$pin_tokens" ]]; then
  echo 'no CORE_REV-style pin identifiers found' >&2
  exit 1
fi

while IFS= read -r token; do
  if ! rg -q --fixed-strings "$token" docs/client-rules.md; then
    echo "undocumented core pin: $token" >&2
    exit 1
  fi
done <<< "$pin_tokens"

echo "documented core pins: $(tr '\n' ' ' <<< "$pin_tokens" | sed 's/ $//')"
