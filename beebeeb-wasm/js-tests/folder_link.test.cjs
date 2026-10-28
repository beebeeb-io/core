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
  assert.throws(() => wasm.deriveSharedFolderIndexKey(kc, 64));
});
