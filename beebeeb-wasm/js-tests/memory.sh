#!/usr/bin/env bash
# Task 2254 (decision L17): build the RELEASE nodejs package and scan the WASM
# heap after every audited export (beebeeb-wasm/js-tests/heap_scan.test.cjs).
#
# Needs: cargo + the wasm32-unknown-unknown target, the wasm-bindgen CLI at the
# workspace's wasm-bindgen version (0.2.118), node >= 18.
#   WASM_BINDGEN=/path/to/wasm-bindgen   (default: wasm-bindgen on PATH)
#   BB_HEAP_SCAN_OUT=/tmp/pkg            (default: fresh mktemp dir)
# Any extra arguments are passed to `cargo build` (e.g. --locked).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${BB_HEAP_SCAN_OUT:-$(mktemp -d)}
bindgen=${WASM_BINDGEN:-wasm-bindgen}
target_dir=${CARGO_TARGET_DIR:-$repo/target}
wasm="$target_dir/wasm32-unknown-unknown/release/beebeeb_wasm.wasm"

cd "$repo"
cargo build --release -p beebeeb-wasm --target wasm32-unknown-unknown "$@"
"$bindgen" "$wasm" --target nodejs --out-dir "$out" --out-name beebeeb_wasm
BB_WASM_PKG="$out" BB_WASM_FILE="$wasm" node --test "$here/heap_scan.test.cjs"
