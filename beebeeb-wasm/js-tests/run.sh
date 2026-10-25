#!/usr/bin/env bash
# Node test of the WASM bindings' JS-facing paths, which `cargo test` cannot execute (it has no JS engine).
# Needs wasm-pack and node >= 20. Builds the nodejs package into a temp dir, runs node:test against it.
#   beebeeb-wasm/js-tests/run.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
(cd "$workspace" && wasm-pack build beebeeb-wasm --target nodejs --dev --no-opt --out-dir "$out/pkg" --out-name beebeeb_wasm)
BB_WASM_PKG="$out/pkg" node --test "$here/direct_signed_url.test.cjs"
