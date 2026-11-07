'use strict';
// Core #74 crypto review, P2-7: web reaches the one safety-number format and
// the one email normalisation through WASM, on every row of
// test-vectors/safety_number.json (generated independently with hashlib),
// including the two rows that pin str::trim against JavaScript's trim.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const doc = require(path.join(__dirname, '../../test-vectors/safety_number.json'));

nodeTest('safetyNumber equals every vector row, in both argument orders', () => {
  assert.equal(doc.vectors.length, 8);
  for (const row of doc.vectors) {
    const a = Buffer.from(row.public_key_a_hex, 'hex');
    const b = Buffer.from(row.public_key_b_hex, 'hex');
    assert.equal(wasm.safetyNumber(row.email_a, a, row.email_b, b), row.safety_number, row.name);
    assert.equal(wasm.safetyNumber(row.email_b, b, row.email_a, a), row.safety_number, `${row.name} reversed`);
  }
  assert.throws(() => wasm.safetyNumber('a', new Uint8Array(31), 'b', new Uint8Array(32)), /32 bytes/);
});

nodeTest('normalizeEmail is Rust trim, not JavaScript trim', () => {
  assert.equal(wasm.normalizeEmail('\u0085A@B.test '), 'a@b.test');
  assert.equal(wasm.normalizeEmail('﻿a@b.test'), '﻿a@b.test');
  assert.notEqual(wasm.normalizeEmail('﻿a@b.test'), '﻿a@b.test'.trim(), 'JS trim strips U+FEFF');
});
