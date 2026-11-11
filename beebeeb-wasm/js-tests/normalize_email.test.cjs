'use strict';
// Web reaches core's one email normalisation through WASM, never its own
// String.prototype.trim: the cases below pin str::trim against JavaScript's trim.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);

nodeTest('normalizeEmail is Rust trim, not JavaScript trim', () => {
  assert.equal(wasm.normalizeEmail('\u0085A@B.test '), 'a@b.test');
  assert.equal(wasm.normalizeEmail('﻿a@b.test'), '﻿a@b.test');
  assert.notEqual(wasm.normalizeEmail('﻿a@b.test'), '﻿a@b.test'.trim(), 'JS trim strips U+FEFF');
});
