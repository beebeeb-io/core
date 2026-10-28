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

// L8 uses the same envelope encoding as L6 with its own purpose label.
test('L8 owner file-key exports open the independent Python KAT and round-trip', () => {
  const v = vector('owner_wrapped_file_key');
  const master = bytes(v.master_key_hex);
  assert.equal(hex(wasm.unwrapOwnerFileKey(master, v.file_id, bytes(v.expected_frame_hex))), v.child_key_hex);
  const wrap = wasm.wrapOwnerFileKey(master, v.file_id, bytes(v.child_key_hex));
  assert.equal(wrap.length, 60);
  assert.equal(hex(wasm.unwrapOwnerFileKey(master, v.file_id, wrap)), v.child_key_hex);
  assert.throws(() => wasm.unwrapOwnerFileKey(master, v.folder_id, wrap), /decryption failed/);
  assert.throws(() => wasm.unwrapOwnerFileKey(new Uint8Array(32).fill(0xff), v.file_id, wrap), /decryption failed/);
  assert.throws(() => wasm.unwrapFolderCustody(master, v.file_id, wrap), /decryption failed/);
  const custody = wasm.wrapFolderCustody(master, v.file_id, bytes(v.child_key_hex));
  assert.throws(() => wasm.unwrapOwnerFileKey(master, v.file_id, custody), /decryption failed/);
});

const { createCipheriv, hkdfSync } = require('node:crypto');
const sealFrame = (key, plaintext, aad = Buffer.alloc(0)) => {
  const nonce = Buffer.alloc(12, 0x37);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
};

test('L8 refuses the item own v1 content, legacy name and old owner format', () => {
  const v = vector('owner_wrapped_file_key');
  const master = bytes(v.master_key_hex);
  const legacy = wasm.derive_file_key(master, new TextEncoder().encode(v.file_id));
  for (const known of [Buffer.alloc(32, 0x55), Buffer.from('{"mime_type":null,"name":"test"}'), bytes(v.child_key_hex)]) {
    const frame = sealFrame(legacy, known);
    assert.equal(frame.length, 60);
    assert.throws(() => wasm.unwrapOwnerFileKey(master, v.file_id, frame), /decryption failed/);
  }
});

test('L8 authenticates AAD in both directions', () => {
  const v = vector('owner_wrapped_file_key');
  const master = bytes(v.master_key_hex);
  const context = Buffer.from('beebeeb-owner-file-key-v1' + v.file_id);
  const purpose = Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), context, 32));
  const noAad = sealFrame(purpose, bytes(v.child_key_hex));
  assert.throws(() => wasm.unwrapOwnerFileKey(master, v.file_id, noAad), /decryption failed/);
  const frame = wasm.wrapOwnerFileKey(master, v.file_id, bytes(v.child_key_hex));
  assert.throws(() => wasm.decrypt_chunk(purpose, frame.slice(0, 12), frame.slice(12)), /decryption failed/);
});

test('L8 rejects invalid key/frame lengths and empty record IDs', () => {
  const key = new Uint8Array(32);
  assert.throws(() => wasm.wrapOwnerFileKey(new Uint8Array(31), 'f', key), /master_key must be exactly 32 bytes/);
  assert.throws(() => wasm.wrapOwnerFileKey(key, 'f', new Uint8Array(33)), /key must be exactly 32 bytes/);
  for (const length of [0, 12, 28, 59, 61, 92]) {
    assert.throws(() => wasm.unwrapOwnerFileKey(key, 'f', new Uint8Array(length)), /must be 60 bytes/);
  }
  assert.throws(() => wasm.wrapOwnerFileKey(key, '', key), /record id must not be empty/);
  assert.throws(() => wasm.unwrapOwnerFileKey(key, '', new Uint8Array(60)), /record id must not be empty/);
});

test('L9 invite owner copy vector and purpose binding', () => {
  const v = vector('invite_owner_copy_v1');
  const master = bytes(v.master_key_hex);
  const key = bytes(v.plaintext_hex);
  assert.equal(hex(wasm.unwrapInviteOwnerCopy(master, v.record_id, bytes(v.wrapped_hex))), v.plaintext_hex);
  const copy = wasm.wrapInviteOwnerCopy(master, v.record_id, key);
  assert.equal(hex(wasm.unwrapInviteOwnerCopy(master, v.record_id, copy)), v.plaintext_hex);
  assert.throws(() => wasm.unwrapInviteOwnerCopy(master, 'other', copy));
  assert.throws(() => wasm.unwrapFolderCustody(master, v.record_id, copy));
  // A purpose-bound copy never opens as a legacy one.
  assert.equal(wasm.openLegacyInviteOwnerCopy(master, v.record_id, copy, []), undefined);
});

test('L9 legacy owner copy opens only when proven over the server rows, in one call', () => {
  const enc = new TextEncoder();
  const master = new Uint8Array(32).fill(7);
  const folderId = '11111111-1111-4111-8111-111111111111';
  const folderKey = new Uint8Array(32).fill(0xf8); // 0xF8 never occurs in UTF-8
  const seal = (key, plaintext) => {
    const r = wasm.encrypt_chunk(key, plaintext);
    return new Uint8Array([...r.nonce, ...r.ciphertext]);
  };
  const b64 = (b) => Buffer.from(b).toString('base64');
  const nameKey = wasm.derive_file_key(master, enc.encode(folderId));
  const ownerRow = (id, key = folderKey) => ({ file_id: id, encrypted_file_key: b64(seal(key, wasm.derive_file_key(master, enc.encode(id)))) });
  const legacy = seal(nameKey, folderKey);
  const proof = ownerRow('22222222-2222-4222-8222-222222222222');
  const foreign = { file_id: '33333333-3333-4333-8333-333333333333', encrypted_file_key: b64(seal(folderKey, new Uint8Array(32).fill(0x5a))) };

  assert.equal(hex(wasm.openLegacyInviteOwnerCopy(master, folderId, legacy, [foreign, proof])), hex(folderKey));
  assert.equal(wasm.openLegacyInviteOwnerCopy(master, folderId, legacy, [foreign]), undefined);
  assert.equal(wasm.openLegacyInviteOwnerCopy(master, folderId, legacy, []), undefined);
  // Malformed rows are skipped, not fatal.
  assert.equal(hex(wasm.openLegacyInviteOwnerCopy(master, folderId, legacy, [{}, { file_id: 'x', encrypted_file_key: '%%' }, proof])), hex(folderKey));
  // The cap: 64 distinct non-proving ids first, then the proof, is not proven.
  const junk = Array.from({ length: 64 }, (_, i) => ({ ...foreign, file_id: `junk-${i}` }));
  assert.equal(wasm.openLegacyInviteOwnerCopy(master, folderId, legacy, [...junk, proof]), undefined);
  assert.equal(hex(wasm.openLegacyInviteOwnerCopy(master, folderId, legacy, [...junk.slice(1), proof])), hex(folderKey));

  // The folder's own name blob ({"name":"Docs","mime_type":null} is 32 bytes)
  // is never a key, even with a row the server could build from a leaked child key.
  const name = enc.encode('{"name":"Docs","mime_type":null}');
  assert.equal(name.length, 32);
  const nameBlob = seal(nameKey, name);
  assert.equal(wasm.openLegacyInviteOwnerCopy(master, folderId, nameBlob, [ownerRow(proof.file_id, name)]), undefined);

  assert.throws(() => wasm.openLegacyInviteOwnerCopy(master, folderId, legacy, 'rows'), /rows must be an array/);
  assert.throws(() => wasm.openLegacyInviteOwnerCopy(new Uint8Array(31), folderId, legacy, []), /master_key must be exactly 32 bytes/);
});
