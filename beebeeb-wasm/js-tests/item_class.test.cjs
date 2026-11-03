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

test('a row sealed like the shipped uploader opens as Unbound and names under C', () => {
  // web upload-request.tsx and the CLI send path: empty request-wrap and seal
  // ids, name sealed under the content key C.
  const rPriv = bytes('11'.repeat(32));
  const rPub = wasm.derive_x25519_public(rPriv);
  const contentKey = bytes('22'.repeat(32));
  const wrap = wasm.wrap_request_private(master(), new Uint8Array(0), rPriv);
  const sealed = wasm.seal_to_request(rPub, new Uint8Array(0), contentKey);
  const name = wasm.encrypt_name_for(contentKey, 'upload.bin', null, 0);

  const row = wasm.resolveRequestRow(
    master(),
    O_ID,
    new Uint8Array(0),
    wrap.wrapped,
    wrap.nonce,
    sealed.e_pub,
    sealed.wrapped_key,
    name,
  );
  assert.equal(row.seal, 'unbound');
  assert.equal(row.nameOrigin, 'request_content');
  assert.equal(row.name, 'upload.bin');
  // D-P2: the result carries a decrypt-only content handle, never the raw
  // content key C or the name key (which IS C for this row).
  assert.equal(row.contentKey, undefined);
  assert.equal(row.nameKey, undefined);
  assert.equal(row.renameTarget.origin, 'derived');
  assert.equal(row.renameTarget.pin, 0);
  assert.equal(row.renameTarget.key, undefined);
  assert.deepEqual(Object.keys(row).sort(), [
    'chunkFormat',
    'content',
    'mimeType',
    'name',
    'nameOrigin',
    'renameTarget',
    'seal',
  ]);
  assert.equal(row.content instanceof wasm.WasmRequestContentReader, true);
  assert.equal(row.content.fileId, O_ID);
  assert.equal(row.content.chunkFormat, 0);

  // Reading still works: a v1 frame under C opens through a fresh decryptor.
  const plaintext = new TextEncoder().encode('the request upload');
  const blob = wasm.encrypt_chunk(contentKey, plaintext);
  const frame = new Uint8Array([...blob.nonce, ...blob.ciphertext]);
  const dec = row.content.decryptor();
  assert.equal(hex(dec.pushFrame(frame)), hex(plaintext));
  assert.equal(dec.chunksDecrypted, 1);
  assert.equal(dec.finish().chunk_count, 1);

  // The same v1 frame opens through openFrame on this unrecorded (pin 0) reader.
  assert.equal(
    hex(row.content.openFrame(new Uint8Array(0), 0, true, 1, frame)),
    hex(plaintext),
  );

  // §15/A9: a rename is ALWAYS sealed under the string-convention key derived
  // from the item id, never under C (which the anonymous uploader holds). The
  // sealer is the only path: the resolver exposed no sealing key.
  const renamed = wasm.sealRequestRename(master(), O_ID, 0, 'renamed.bin', null);
  const stringKey = wasm.derive_file_key(master(), new TextEncoder().encode(O_ID));
  assert.equal(wasm.decrypt_file_metadata_with_key(stringKey, renamed).name, 'renamed.bin');
  assert.throws(() => wasm.decrypt_file_metadata_with_key(contentKey, renamed));
  assert.notEqual(hex(stringKey), hex(contentKey));
});

test('a bound request row opens as Bound with a derived rename target', () => {
  const rPriv = bytes('11'.repeat(32));
  const rPub = wasm.derive_x25519_public(rPriv);
  const contentKey = bytes('22'.repeat(32));
  const wrap = wasm.wrap_request_private(master(), new Uint8Array(0), rPriv);
  const sealed = wasm.seal_to_request(rPub, new TextEncoder().encode(O_ID), contentKey);
  const name = wasm.encrypt_name_with_chunk_format(master(), O_ID, 'upload.bin', null, 2);

  const row = wasm.resolveRequestRow(
    master(),
    O_ID,
    new Uint8Array(0),
    wrap.wrapped,
    wrap.nonce,
    sealed.e_pub,
    sealed.wrapped_key,
    name,
  );
  assert.equal(row.seal, 'bound');
  assert.equal(row.nameOrigin, 'derived');
  assert.equal(row.name, 'upload.bin');
  assert.equal(row.contentKey, undefined);
  assert.equal(row.nameKey, undefined);
  assert.equal(row.renameTarget.origin, 'derived');
  assert.equal(row.renameTarget.pin, 2);
  assert.equal(row.renameTarget.key, undefined);

  // The row records chunkFormat 2, so its reader is pinned to v2: a v1
  // frame under C is refused. (The unbound test above shows the open path.)
  assert.equal(row.content instanceof wasm.WasmRequestContentReader, true);
  const plaintext = new TextEncoder().encode('bound upload');
  const v1 = wasm.encrypt_chunk(contentKey, plaintext);
  const v1Frame = new Uint8Array([...v1.nonce, ...v1.ciphertext]);
  assert.throws(() => row.content.decryptor().pushFrame(v1Frame));

  // openFrame is the guard's other entry point: a v1 frame under the same C is
  // refused by this V2-pinned reader, with the error that names the pin.
  assert.throws(
    () => row.content.openFrame(new Uint8Array(0), 0, true, 1, v1Frame),
    /records chunk format 2/,
  );
});

test('a request-row content reader range-reads, retries and exposes no key', () => {
  const rPriv = bytes('11'.repeat(32));
  const rPub = wasm.derive_x25519_public(rPriv);
  // C is derived under O_ID so the WASM encryptor below can write its frames.
  const contentKey = wasm.derive_file_key(master(), new TextEncoder().encode(O_ID));
  const wrap = wasm.wrap_request_private(master(), new Uint8Array(0), rPriv);
  const sealed = wasm.seal_to_request(rPub, new TextEncoder().encode(O_ID), contentKey);

  // A BOUND row whose name is sealed under the legacy binary convention, so its
  // name key differs from C: building the reader from the name key (a mutant)
  // cannot open these frames.
  const binaryId = Uint8Array.from(Buffer.from(O_ID.replace(/-/g, ''), 'hex'));
  const binaryKey = wasm.derive_file_key(master(), binaryId);
  assert.notEqual(hex(binaryKey), hex(contentKey));
  const name = wasm.encrypt_name_for(binaryKey, 'upload.bin', null, 2);

  const row = wasm.resolveRequestRow(
    master(),
    O_ID,
    new Uint8Array(0),
    wrap.wrapped,
    wrap.nonce,
    sealed.e_pub,
    sealed.wrapped_key,
    name,
  );
  assert.equal(row.seal, 'bound');
  assert.equal(row.nameOrigin, 'derived_binary');
  assert.equal(row.chunkFormat, 2);

  // The reader exposes no key. `row` has exactly its documented keys.
  assert.deepEqual(Object.keys(row).sort(), [
    'chunkFormat',
    'content',
    'mimeType',
    'name',
    'nameOrigin',
    'renameTarget',
    'seal',
  ]);
  for (const keyName of ['key', 'contentKey', 'nameKey', 'rawKey', 'keyBytes']) {
    assert.equal(row.content[keyName], undefined, keyName);
  }
  assert.equal(row.content.fileId, O_ID);
  assert.equal(row.content.chunkFormat, 2);

  // One v2 upload under C, bound to O_ID.
  const plaintext = new TextEncoder().encode('0123456789abcdef0123456789abcdef0123456789abcdef');
  const enc = wasm.WasmChunkEncryptor.withChunkSize(master(), O_ID, BigInt(plaintext.length), 16n).withRecordedPin(2);
  const frames = [];
  for (let i = 0; i < plaintext.length; i += 16) frames.push(enc.pushChunk(plaintext.slice(i, i + 16)));
  enc.finish();
  const versionId = frames[0].slice(0, 12);

  // Range read frame 2 without opening frames 0 and 1.
  assert.equal(
    hex(row.content.openFrame(versionId, 2, true, 2, frames[2])),
    hex(plaintext.slice(32, 48)),
  );

  // A fresh decryptor after the first failed mid-stream.
  const first = row.content.decryptor();
  assert.equal(hex(first.pushFrame(frames[0])), hex(plaintext.slice(0, 16)));
  assert.throws(() => first.pushFrame(frames[2]));
  const second = row.content.decryptor();
  const out = [];
  for (const frame of frames) out.push(...second.pushFrame(frame));
  assert.equal(hex(Uint8Array.from(out)), hex(plaintext));
  assert.equal(second.finish().chunk_count, 3);
});

test('the request content reader exposes exactly its documented JS surface', () => {
  // No key getter and no extra helper: a new member on the prototype is a
  // new way for JS to reach the reader's key, so the list is exact.
  assert.deepEqual(
    Object.getOwnPropertyNames(wasm.WasmRequestContentReader.prototype).sort(),
    [
      '__destroy_into_raw',
      'chunkFormat',
      'constructor',
      'decryptor',
      'fileId',
      'free',
      'openFrame',
    ],
  );
});

test('mintGuestItemId needs no master key and always mints an F id', () => {
  for (let i = 0; i < 64; i++) {
    const id = wasm.mintGuestItemId();
    assert.equal(wasm.isForeignItemId(id), true, id);
  }
});
