'use strict';
// Task 2237b, decision L6: the web's owner copies (folder custody, a link's
// K_c and token) and the link passphrase stretch go through core, never
// through a hand-rolled JS seal. These pin the WASM exports against core's
// published vectors (test-vectors/vectors.json) and the purpose separation.
const assert = require('node:assert/strict');
const test = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);
const vectors = require('../../test-vectors/vectors.json').vectors;

const vector = (name) => vectors.find((v) => v.name === name);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');

test('custody, link-owner key and link-owner token open the published vectors', () => {
  const custody = vector('folder_custody_v1');
  assert.equal(
    hex(wasm.unwrapFolderCustody(bytes(custody.master_key_hex), custody.record_id, bytes(custody.wrapped_hex))),
    custody.plaintext_hex,
  );
  const ownerKey = vector('link_owner_key_v1');
  assert.equal(
    hex(wasm.unwrapLinkOwnerKey(bytes(ownerKey.master_key_hex), ownerKey.record_id, bytes(ownerKey.wrapped_hex))),
    ownerKey.plaintext_hex,
  );
  const ownerToken = vector('link_owner_token_v1');
  assert.equal(
    hex(wasm.unwrapLinkOwnerToken(bytes(ownerToken.master_key_hex), ownerToken.record_id, bytes(ownerToken.wrapped_hex))),
    ownerToken.plaintext_hex,
  );
});

test('each wrap round-trips and opens only for its own record and purpose', () => {
  const master = new Uint8Array(32).fill(0x40);
  const key = new Uint8Array(32).fill(0x60);
  const custody = wasm.wrapFolderCustody(master, 'folder-a', key);
  assert.equal(custody.length, 60);
  assert.deepEqual(Array.from(wasm.unwrapFolderCustody(master, 'folder-a', custody)), Array.from(key));
  assert.throws(() => wasm.unwrapFolderCustody(master, 'folder-b', custody), /decryption failed/);
  assert.throws(() => wasm.unwrapFolderCustody(new Uint8Array(32).fill(0x41), 'folder-a', custody), /decryption failed/);

  const ownerKey = wasm.wrapLinkOwnerKey(master, 'share-a', key);
  assert.deepEqual(Array.from(wasm.unwrapLinkOwnerKey(master, 'share-a', ownerKey)), Array.from(key));
  assert.throws(() => wasm.unwrapLinkOwnerKey(master, 'share-b', ownerKey), /decryption failed/);
  // Purpose separation: a link-owner key is not a custody record, nor a token.
  assert.throws(() => wasm.unwrapFolderCustody(master, 'share-a', ownerKey), /decryption failed/);
  assert.throws(() => wasm.unwrapLinkOwnerToken(master, 'share-a', ownerKey), /decryption failed/);

  const token = new TextEncoder().encode('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
  const ownerToken = wasm.wrapLinkOwnerToken(master, 'share-a', token);
  assert.equal(ownerToken.length, 12 + token.length + 16);
  assert.deepEqual(Array.from(wasm.unwrapLinkOwnerToken(master, 'share-a', ownerToken)), Array.from(token));
  assert.throws(() => wasm.unwrapLinkOwnerKey(master, 'share-a', ownerToken), /decryption failed|32 bytes/);
});

test('a legacy unbound owner copy is refused as custody', () => {
  // key_wrap_v1: the old no-AAD AES-GCM wrap shape. The custody reader must
  // never accept it, whatever key it is presented under.
  const legacy = vector('key_wrap_v1');
  assert.throws(
    () => wasm.unwrapFolderCustody(bytes(legacy.wrapper_key_hex), 'folder-a', bytes(legacy.wrapped_hex)),
    /decryption failed/,
  );
});

test('bad lengths are refused before any crypto', () => {
  const key = new Uint8Array(32);
  assert.throws(() => wasm.wrapFolderCustody(new Uint8Array(31), 'f', key), /master_key must be exactly 32 bytes/);
  assert.throws(() => wasm.wrapFolderCustody(key, 'f', new Uint8Array(33)), /key must be exactly 32 bytes/);
  assert.throws(() => wasm.unwrapFolderCustody(key, 'f', new Uint8Array(59)), /custody wrap must be 60 bytes/);
  assert.throws(() => wasm.wrapLinkOwnerKey(key, 's', new Uint8Array(31)), /key must be exactly 32 bytes/);
  assert.throws(() => wasm.unwrapLinkOwnerToken(key, 's', new Uint8Array(27)), /wrap is too short/);
});

test('the passphrase stretch matches the vectors, NFC and NFD alike, and refuses empty', () => {
  for (const name of ['folder_link_passphrase', 'folder_link_passphrase_nfd']) {
    const v = vector(name);
    const stretch = wasm.deriveFolderLinkPassphraseStretch(v.passphrase, v.token);
    assert.equal(hex(stretch), v.stretch_hex, name);
    assert.equal(hex(wasm.combineFolderLinkKey(bytes(v.k_c_hex), stretch)), v.link_key_hex, name);
  }
  assert.throws(() => wasm.deriveFolderLinkPassphraseStretch('', 'tok'), /must not be empty/);
});
