'use strict';
// Task 1922 round 2: the JS surface of the client-metadata handle. `cargo test`
// cannot see the glue wasm-bindgen generates, so the JS names and the
// per-row batch behaviour are pinned here.
const assert = require('node:assert/strict');
const test = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);

const RECORD = '19220000-0000-4000-8000-000000000001';
const DEVICE = '19220000-0000-4000-8000-0000000000AA';

const handle = () => new wasm.ClientMetaKey(new Uint8Array(32).fill(0x40));

test('the documented JS names exist', () => {
  assert.equal(typeof wasm.ClientMetaKey.prototype.openMany, 'function');
  assert.equal(typeof wasm.ClientMetaKey.prototype.open_many, 'undefined');
  assert.equal(typeof wasm.fitForSeal, 'function');
  assert.equal(typeof wasm.fit_for_seal, 'undefined');
});

test('openMany isolates every per-row problem', () => {
  const key = handle();
  const host = key.seal(RECORD, null, 1, 'MacBook-Air');
  const path = key.seal(RECORD, DEVICE, 3, '/Users/guus/Taxes');
  const rows = key.openMany([
    { recordKey: RECORD, deviceKey: null, field: 1, envelope: host },
    // A null envelope fails this row only.
    { recordKey: RECORD, field: 1, envelope: null },
    { recordKey: RECORD, deviceKey: DEVICE, field: 3, envelope: path },
    // 257 must be refused, not wrapped to 1.
    { recordKey: RECORD, deviceKey: DEVICE, field: 257, envelope: host },
    { recordKey: 'not-a-uuid', field: 1, envelope: host },
    // A row that is not an object at all.
    'not-a-row',
  ]);
  assert.equal(rows.length, 6);
  assert.equal(rows[0].ok, true);
  assert.equal(rows[0].value, 'MacBook-Air');
  assert.equal(rows[1].ok, false);
  assert.equal(rows[1].value, undefined);
  assert.equal(rows[2].ok, true);
  assert.equal(rows[2].value, '/Users/guus/Taxes');
  for (const row of rows.slice(3)) {
    assert.equal(row.ok, false);
    assert.equal(row.value, undefined);
  }
  key.free();
});

test('only a bad top-level items value throws', () => {
  const key = handle();
  assert.throws(() => key.openMany({ not: 'an array' }), /items must be an array/);
  key.free();
});

test('field 257 is refused by seal and open', () => {
  const key = handle();
  assert.throws(() => key.seal(RECORD, null, 257, 'x'), /field|client-meta/);
  assert.throws(() => key.open(RECORD, null, 257, 'bbcm1.x'), /field|client-meta/);
  key.free();
});

test('fitForSeal keeps a char-boundary tail within 1024 bytes', () => {
  assert.equal(wasm.fitForSeal('short'), 'short');
  const fitted = wasm.fitForSeal('é'.repeat(700));
  assert.ok(new TextEncoder().encode(fitted).length <= 1024);
  assert.ok(fitted.startsWith('…'));
});
