'use strict';
// Task 2275 L12-L14: the item id classes, the opaque handles core mints, the
// WASM resolver's write target, the new-item/target sealers, request rows and
// childWrapMatches.
const assert = require('node:assert/strict');
const test = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);
const vectors = require('../../test-vectors/vectors.json').vectors;

const vector = (name) => vectors.find((v) => v.name === name);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');
const master = () => bytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');

const F_ID = '11111111-1111-8111-8111-111111111111';
const O_ID = '66666666-6666-4666-8666-666666666666';
const KEY = bytes('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');

// kind: 1 = file, 2 = folder (task 2275 L12/L13).
const FILE = 1;
const FOLDER = 2;

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

test('core mints canonical, class-correct handles with a resume tag', () => {
  const foreign = wasm.newForeignItemId(master());
  const owner = wasm.newOwnerItemId(master());
  assert.equal(foreign.idText.length, 36);
  assert.equal(owner.idText.length, 36);
  assert.equal(foreign.tag.length, 32, 'the resume tag is HMAC-SHA256');
  assert.equal(owner.tag.length, 32);
  assert.equal(wasm.isForeignItemId(foreign.idText), true);
  assert.equal(wasm.isForeignItemId(owner.idText), false);
});

test('resume accepts the minted id and tag and refuses anything else', () => {
  const minted = wasm.newOwnerItemId(master());
  const resumed = wasm.resumeNewItemId(master(), minted.idText, minted.tag);
  assert.equal(resumed.idText, minted.idText);
  assert.equal(hex(resumed.tag), hex(minted.tag));

  const tampered = minted.tag.slice();
  tampered[0] ^= 1;
  assert.throws(() => wasm.resumeNewItemId(master(), minted.idText, tampered));

  const other = wasm.newOwnerItemId(master());
  assert.throws(() => wasm.resumeNewItemId(master(), minted.idText, other.tag));

  // A server-echoed id: the same tag, one hex digit changed.
  const echoed = minted.idText.slice(0, -1) + (minted.idText.endsWith('0') ? '1' : '0');
  assert.throws(() => wasm.resumeNewItemId(master(), echoed, minted.tag));

  const short = minted.tag.slice(0, 31);
  assert.throws(() => wasm.resumeNewItemId(master(), minted.idText, short));
});

test('an owner row resolves by derivation and carries a write target', () => {
  const name = wasm.encrypt_name_with_chunk_format(master(), O_ID, 'a.txt', null, 0);
  const resolved = wasm.resolveOwnedKey(master(), O_ID, FILE, undefined, name);
  assert.equal(resolved.origin, 'derived');
  assert.equal(resolved.name.name, 'a.txt');
  assert.equal(resolved.contentKey, null);
  assert.equal(resolved.writeTarget.itemId, O_ID);
  assert.equal(resolved.writeTarget.pin, 0);

  // A replacement sealed through the target is what the row reads back.
  const renamed = wasm.encryptNameForTarget(resolved.writeTarget, 'renamed.txt', null);
  const again = wasm.resolveOwnedKey(master(), O_ID, FILE, undefined, renamed);
  assert.equal(again.name.name, 'renamed.txt');
  assert.equal(again.writeTarget.itemId, O_ID);
});

test('a foreign row resolves by its L8 envelope and never by derivation', () => {
  const wrap = wasm.wrapOwnerFileKey(master(), F_ID, KEY);
  const name = wasm.encrypt_name_for(KEY, 'adopted.txt', 'text/plain', 0);
  const resolved = wasm.resolveOwnedKey(master(), F_ID, FILE, wrap, name);
  assert.equal(resolved.origin, 'owner_wrap');
  assert.equal(hex(resolved.key), hex(KEY));
  assert.equal(resolved.contentKey, null);
  assert.equal(resolved.writeTarget.itemId, F_ID);
  assert.equal(resolved.name.mimeType, 'text/plain');

  // A6: the derived key opens the name, but no envelope/wrap means no key.
  const derivedName = wasm.encrypt_name_with_chunk_format(master(), F_ID, 'x.txt', null, 0);
  assert.throws(() => wasm.resolveOwnedKey(master(), F_ID, FILE, undefined, derivedName));
});

test('L8 refuses an owner id', () => {
  assert.throws(() => wasm.wrapOwnerFileKey(master(), O_ID, KEY));
});

test('a plaintext-named file needs its first chunk; a folder does not', () => {
  assert.throws(
    () => wasm.resolveOwnedKey(master(), O_ID, FILE, undefined, 'legacy.bin'),
    'a file with a plaintext name is identified by its first content chunk',
  );
  const folder = wasm.resolveOwnedKey(master(), O_ID, FOLDER, undefined, 'Legacy folder');
  assert.equal(folder.origin, 'derived');
  assert.equal(folder.contentKey, null);
  assert.equal(folder.writeTarget.itemId, O_ID);
});

test('an unknown row kind is refused rather than guessed', () => {
  assert.throws(() => wasm.resolveOwnedKey(master(), O_ID, 3, undefined, 'x'));
  assert.throws(() => wasm.resolveOwnedKey(master(), O_ID, 0, undefined, 'x'));
});

test('the new-item sealer writes under the id core minted', () => {
  const id = wasm.newOwnerItemId(master());
  const sealed = wasm.encryptNameForNewItem(id, 'new.txt', null, 0);
  const resolved = wasm.resolveOwnedKey(master(), id.idText, FILE, undefined, sealed);
  assert.equal(resolved.name.name, 'new.txt');
  assert.equal(resolved.origin, 'derived');
  assert.equal(resolved.writeTarget.itemId, id.idText);

  // P2 7: an unknown chunk-format code is refused, never read as "unrecorded".
  assert.throws(() => wasm.encryptNameForNewItem(id, 'x.txt', null, 7));
  assert.throws(() => wasm.encryptNameForNewItem(id, 'x.txt', null, 1));
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
