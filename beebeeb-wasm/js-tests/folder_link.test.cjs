'use strict';
// Task 2237b: a shared folder's index is sealed under the folder key, and the
// public link combiner matches core's pinned KAT bytes.
const assert = require('node:assert/strict');
const test = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);

const ramp = (start) => Uint8Array.from({ length: 32 }, (_, i) => start + i);
const hex = (b) => Buffer.from(b).toString('hex');

test('folder-keyed index round-trips and rejects another key', () => {
  const folderKey = new Uint8Array(32).fill(0x5a);
  const idx = wasm.WasmSearchIndex.build([{ fileId: 'f1', name: 'NF_song.mp3' }], 64);
  const shards = idx.encryptShardsWithFolderKey(folderKey);
  assert.ok(shards.length > 0);
  const restored = wasm.WasmSearchIndex.fromEncryptedShardsWithFolderKey(folderKey, shards, 64);
  assert.deepEqual(restored.query('nf'), ['f1']);
  assert.throws(
    () => wasm.WasmSearchIndex.fromEncryptedShardsWithFolderKey(new Uint8Array(32).fill(0x11), shards, 64),
    /decryption failed: ciphertext is invalid or key is wrong/,
    'a different key must not open the shards',
  );
});

test('combiner and bucket key match the published vectors', () => {
  const kc = ramp(0x80);
  assert.equal(hex(wasm.combineFolderLinkKey(kc)), '5fb510b7068bfa1e9290e8a8ed296da4f610e5451a567699dc48e9bc3bd1badc');
  assert.equal(
    hex(wasm.combineFolderLinkKey(kc, ramp(0xa0))),
    '1b87f03afb4b81c4b17c1a6f74648a4e725d1d5c1e0750b5767df89ee653b13b',
  );
  assert.equal(hex(wasm.deriveSharedFolderIndexKey(kc, 0)), 'a4a09ac7b7e2d845a05c1b67930024a043c6bda3ed280f5fcf627ddb15d1208c');
  assert.throws(() => wasm.deriveSharedFolderIndexKey(kc, 64), /bucket must be less than 64/);
});

test('all index constructors enforce the 64-bucket layout', () => {
  const key = new Uint8Array(32).fill(0x5a);
  const constructors = [
    (count) => new wasm.WasmSearchIndex(count),
    (count) => wasm.WasmSearchIndex.build([], count),
    (count) => wasm.WasmSearchIndex.fromEncryptedShards(key, [], count),
    (count) => wasm.WasmSearchIndex.fromEncryptedShardsWithFolderKey(key, [], count),
  ];
  for (const construct of constructors) {
    for (const count of [65, 0xffffffff]) {
      assert.throws(() => construct(count), /num_shards must be at most 64/);
    }
    for (const count of [0, 1, 64]) {
      const idx = construct(count);
      assert.equal(idx.numShards, Math.max(1, count));
      idx.free();
    }
  }
  assert.equal(wasm.deriveSharedFolderIndexKey(key, 63).length, 32);
});

test('combiner refuses invalid fragment and passphrase stretch lengths', () => {
  assert.throws(() => wasm.combineFolderLinkKey(new Uint8Array(31)), /k_c must be 32 bytes/);
  assert.throws(
    () => wasm.combineFolderLinkKey(new Uint8Array(32), new Uint8Array(31)),
    /passphrase stretch must be 32 bytes/,
  );
});
