'use strict';
// C3 move 1's WASM surface: the one byte formatter. Every case in
// test-vectors/consolidation/format.json goes through a wasm export — the SI
// formatter that already shipped (`storage_format_si`) and the two new ones.
// BB_VECTOR_PATH points the same test at a mutated copy for the red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/format.json'));
// The byte count is an `i64` on the core side, so the wasm glue takes a BigInt
// (exactly like the long-standing `storage_format_si`). JSON.parse hands a
// 64-bit count back as a double, and i64::MAX rounds UP past what i64 holds,
// so a value above the maximum is clamped back to it.
const I64_MAX = 9223372036854775807n;
const b = (n) => {
  const v = BigInt(n);
  return v > I64_MAX ? I64_MAX : v;
};

nodeTest('the format vector: SI, binary and compact agree with every case', () => {
  assert.equal(vectors.cases.length, 24, 'every case in format.json is exercised');

  for (const c of vectors.cases) {
    let got;
    if (c.kind === 'si') {
      got = wasm.storage_format_si(b(c.bytes));
    } else if (c.kind === 'binary') {
      got = wasm.formatBinary(b(c.bytes));
    } else if (c.kind === 'compact') {
      got = wasm.formatCompact(b(c.bytes), c.decimals);
    } else {
      assert.fail(`${c.id}: unknown vector kind ${c.kind}`);
    }
    assert.equal(got, c.expected, c.id);
  }
});

nodeTest('the two new formatters are the same rule the storage formatter uses', () => {
  // 1,024 bytes is 1 KiB but 1 KB: the unit base is the only difference.
  assert.equal(wasm.formatBinary(b(1024)), '1 KiB');
  assert.equal(wasm.storage_format_si(b(1024)), '1 KB');
  // A negative count is never scaled, in any of the three.
  assert.equal(wasm.formatBinary(b(-1500)), '-1500 B');
  assert.equal(wasm.formatCompact(b(-1500), 2), '-1500 B');
  assert.equal(wasm.storage_format_si(b(-1500)), '-1500 B');
});
