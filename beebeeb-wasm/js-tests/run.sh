#!/usr/bin/env bash
# The JS surface of beebeeb-wasm, judged the way a web client sees it. `cargo test` cannot: it has no JS engine and
# never parses the glue wasm-bindgen generates.
#   1. builds the package for BOTH targets (nodejs, web) into a temp dir;
#   2. `node --check` on both glue files (the web one is an ES module, checked as .mjs);
#   3. `tsc --noEmit --strict` on both .d.ts files;
#   4. runs the node:test suite against the nodejs build.
# Needs wasm-pack, node >= 20 and tsc (or npx, which fetches the pinned typescript below).
#   beebeeb-wasm/js-tests/run.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

for target in nodejs web; do
  (cd "$workspace" && wasm-pack build beebeeb-wasm --target "$target" --dev --no-opt --out-dir "$out/$target" --out-name beebeeb_wasm)
done

echo "== node --check: the generated glue parses"
node --check "$out/nodejs/beebeeb_wasm.js"
cp "$out/web/beebeeb_wasm.js" "$out/web/beebeeb_wasm.mjs"
node --check "$out/web/beebeeb_wasm.mjs"

echo "== tsc --noEmit: the generated declarations parse and type-check"
if command -v tsc >/dev/null 2>&1; then
  tsc=(tsc)
else
  tsc=(npx --yes --package typescript@5.6.3 tsc)
fi
(cd "$out" && "${tsc[@]}" --noEmit --strict --target es2022 --lib es2022,dom,esnext.disposable nodejs/beebeeb_wasm.d.ts web/beebeeb_wasm.d.ts)

echo "== tsc --noEmit: what a TypeScript consumer sees of poll()"
for target in nodejs web; do
  sed "s|./PKG/|./$target/|" "$here/types.check.ts" > "$out/types.$target.check.ts"
done
(cd "$out" && "${tsc[@]}" --noEmit --strict --target es2022 --lib es2022,dom,esnext.disposable types.nodejs.check.ts types.web.check.ts)

echo "== node --test: the real module"
BB_WASM_PKG="$out/nodejs" node --test "$here/direct_signed_url.test.cjs" "$here/direct_poll_shape.test.cjs" "$here/direct_health_shape.test.cjs" "$here/direct_l1_gaps.test.cjs" "$here/folder_link.test.cjs" "$here/folder_owner_wraps.test.cjs" "$here/upper_repair.test.cjs" "$here/client_meta.test.cjs" "$here/item_class.test.cjs" "$here/no_bare_sealers.test.cjs" "$here/l16_labels.test.cjs"
