'use strict';
// SF-0002: a file the iOS File Provider sealed under an uppercase id is readable
// by its owner through core's read-only repair convention. The web export must
// report `upper_repair` and hand back a key that opens the published chunk.
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

test('the name now shows through decryptNameMetadata and the canonical row is "string"', () => {
  const v = vector('upper_repair_v1');
  const meta = wasm.decrypt_name_metadata(bytes(v.master_key_hex), v.file_id, v.name_encrypted);
  assert.equal(meta.name, v.expected_name);
  assert.equal(meta.mime_type, v.expected_mime_type);

  const master = bytes(v.master_key_hex);
  const canonical = wasm.encrypt_name_with_chunk_format(master, v.file_id, 'canonical.txt', null, 0);
  const resolved = wasm.ownerFileKeyForName(master, v.file_id, canonical);
  assert.equal(resolved.convention, 'string');
});

test('a plaintext name and an id with no hex letters behave', () => {
  const v = vector('upper_repair_v1');
  assert.throws(() => wasm.ownerFileKeyForName(bytes(v.master_key_hex), v.file_id, 'plain.txt'));

  const master = bytes(v.master_key_hex);
  const digits = '12345678-1234-4321-8123-123456789012';
  const canonical = wasm.encrypt_name_with_chunk_format(master, digits, 'digits.txt', null, 0);
  assert.equal(wasm.ownerFileKeyForName(master, digits, canonical).convention, 'string');
});
