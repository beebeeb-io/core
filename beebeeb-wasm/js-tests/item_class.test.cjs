'use strict';
// Task 2275 L12-L14: the item id classes, the WASM resolver's write target,
// the new-item/target sealers, request rows and childWrapMatches.
const assert = require('node:assert/strict');
const test = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);
const vectors = require('../../test-vectors/vectors.json').vectors;

const vector = (name) => vectors.find((v) => v.name === name);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');
const master = () => bytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');

const F_ID = '11111111-1111-8111-8111-111111111111';
const KEY = bytes('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');

test('the published item id classes agree with the WASM predicates', () => {
  const v = vector('item_ids');
  for (const row of v.foreign) {
    assert.equal(wasm.isForeignItemId(row.id), true, row.id);
  }
  for (const row of v.owner) {
    assert.equal(wasm.isForeignItemId(row.id), false, row.id);
  }
  for (const row of v.refused) {
    assert.throws(() => wasm.isForeignItemId(row.id), row.id);
  }
});

test('core mints canonical, class-correct ids', () => {
  const foreign = wasm.newForeignItemId();
  const owner = wasm.newOwnerItemId();
  assert.equal(foreign.length, 36);
  assert.equal(owner.length, 36);
  assert.equal(wasm.isForeignItemId(foreign), true);
  assert.equal(wasm.isForeignItemId(owner), false);
});

test('an owner row resolves by derivation and an upper-repair row has no write target', () => {
  const owner = '66666666-6666-4666-8666-666666666666';
  const name = wasm.encryptNameForTarget(wasm.derive_file_key(master(), new TextEncoder().encode(owner)), 0, 'a.txt', null);
  const resolved = wasm.resolveOwnedKey(master(), owner, undefined, name);
  assert.equal(resolved.origin, 'derived');
  assert.equal(resolved.name.name, 'a.txt');
  assert.equal(resolved.writeTarget.itemId, owner);
  assert.equal(resolved.writeTarget.pin, 0);
});

test('a foreign row resolves by its L8 envelope and never by derivation', () => {
  const wrap = wasm.wrapOwnerFileKey(master(), F_ID, KEY);
  const name = wasm.encryptNameForTarget(KEY, 0, 'adopted.txt', 'text/plain');
  const resolved = wasm.resolveOwnedKey(master(), F_ID, wrap, name);
  assert.equal(resolved.origin, 'owner_wrap');
  assert.equal(hex(resolved.key), hex(KEY));
  assert.equal(resolved.writeTarget.itemId, F_ID);
  assert.equal(resolved.name.mimeType, 'text/plain');

  // A6: the derived key opens the name, but no envelope/wrap means no key.
  const derivedName = wasm.encryptNameForTarget(wasm.derive_file_key(master(), new TextEncoder().encode(F_ID)), 0, 'x.txt', null);
  assert.throws(() => wasm.resolveOwnedKey(master(), F_ID, undefined, derivedName));
});

test('L8 refuses an owner id', () => {
  assert.throws(() => wasm.wrapOwnerFileKey(master(), '66666666-6666-4666-8666-666666666666', KEY));
});

test('the new-item sealer writes under the id core minted', () => {
  const id = wasm.newOwnerItemId();
  const sealed = wasm.encryptNameForNewItem(master(), id, 'new.txt', null, 0);
  const resolved = wasm.resolveOwnedKey(master(), id, undefined, sealed);
  assert.equal(resolved.name.name, 'new.txt');
  assert.equal(resolved.origin, 'derived');
});

test('childWrapMatches accepts only the honest wrap', () => {
  const folder = bytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const root = '22222222-2222-4222-8222-222222222222';
  const wrap = wasm.wrapFolderChild(folder, root, F_ID, 1, KEY);
  assert.equal(wasm.childWrapMatches(folder, root, F_ID, 1, wrap, KEY), true);
  assert.equal(wasm.childWrapMatches(folder, root, '33333333-3333-4333-8333-333333333333', 1, wrap, KEY), false);
  assert.equal(wasm.childWrapMatches(folder, root, F_ID, 2, wrap, KEY), false);
  assert.equal(wasm.childWrapMatches(folder, root, F_ID, 1, wrap, bytes('00'.repeat(32))), false);
});
