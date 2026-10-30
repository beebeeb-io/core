'use strict';
// SF-0002: a file the iOS File Provider sealed under an uppercase id is
// readable by its owner only through core's READ-ONLY repair convention. The
// web export must report `upper_repair` and hand back a key that opens the
// published chunk; the shared name reader must NOT gain the uppercase
// candidate (a client that only bumped core would otherwise treat the file as
// writable and re-seal the name under the lowercase key).
const assert = require('node:assert/strict');
const test = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);
const vectors = require('../../test-vectors/vectors.json').vectors;

const vector = (name) => vectors.find((v) => v.name === name);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');

test('ownerFileKeyForName resolves the uppercase vector as upper_repair', () => {
  const v = vector('upper_repair_v1');
  const resolved = wasm.ownerFileKeyForName(bytes(v.master_key_hex), v.file_id, v.name_encrypted);
  assert.equal(resolved.convention, v.expected_convention);
  assert.equal(resolved.convention, 'upper_repair');
  assert.ok(resolved.key instanceof Uint8Array);
  assert.equal(resolved.key.length, 32);

  // The returned key opens the content chunk sealed under the uppercase id.
  const frame = bytes(v.content_frame_hex);
  assert.equal(
    hex(wasm.decrypt_chunk(resolved.key, frame.slice(0, 12), frame.slice(12))),
    v.content_plaintext_hex,
  );
});

test('the shared name reader stays two-convention; the canonical row is "string"', () => {
  const v = vector('upper_repair_v1');
  assert.throws(
    () => wasm.decrypt_name_metadata(bytes(v.master_key_hex), v.file_id, v.name_encrypted),
    'decrypt_name_metadata must not try the uppercase repair',
  );

  const master = bytes(v.master_key_hex);
  const canonical = wasm.encrypt_name_with_chunk_format(master, v.file_id, 'canonical.txt', null, 0);
  const resolved = wasm.ownerFileKeyForName(master, v.file_id, canonical);
  assert.equal(resolved.convention, 'string');
});

test('ownerFileKeyForContent resolves each version on its own (split keys)', () => {
  const v = vector('upper_repair_split_v1');
  const master = bytes(v.master_key_hex);

  assert.equal(wasm.ownerFileKeyForName(master, v.file_id, v.name_encrypted).convention, 'upper_repair');

  const v1 = bytes(v.content_v1_frame_hex);
  const first = wasm.ownerFileKeyForContent(master, v.file_id, v1);
  assert.equal(first.convention, v.expected_content_v1_convention);
  assert.equal(first.convention, 'upper_repair');
  assert.equal(hex(wasm.decrypt_chunk(first.key, v1.slice(0, 12), v1.slice(12))), v.content_v1_plaintext_hex);

  const v2 = bytes(v.content_v2_frame_hex);
  const second = wasm.ownerFileKeyForContent(master, v.file_id, v2);
  assert.equal(second.convention, v.expected_content_v2_convention);
  assert.equal(second.convention, 'string');
  assert.equal(hex(wasm.decrypt_chunk(second.key, v2.slice(0, 12), v2.slice(12))), v.content_v2_plaintext_hex);
});

test('a plaintext name and an id with no hex letters behave', () => {
  const v = vector('upper_repair_v1');
  assert.throws(() => wasm.ownerFileKeyForName(bytes(v.master_key_hex), v.file_id, 'plain.txt'));

  const master = bytes(v.master_key_hex);
  const digits = '12345678-1234-4321-8123-123456789012';
  const canonical = wasm.encrypt_name_with_chunk_format(master, digits, 'digits.txt', null, 0);
  assert.equal(wasm.ownerFileKeyForName(master, digits, canonical).convention, 'string');
});

test('a non-canonical id is refused by both resolvers', () => {
  const v = vector('upper_repair_split_v1');
  const master = bytes(v.master_key_hex);
  assert.throws(() => wasm.ownerFileKeyForName(master, v.file_id_upper, v.name_encrypted));
  assert.throws(() => wasm.ownerFileKeyForContent(master, v.file_id_upper, bytes(v.content_v1_frame_hex)));
});
