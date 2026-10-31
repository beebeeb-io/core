'use strict';
// Task 2275, L16: link labels, guest actor names and the one legacy child
// opener. Pins the WASM exports against core's published vectors (version 15)
// and the bindings both new formats rely on.
const assert = require('node:assert/strict');
const test = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);
const vectors = require('../../test-vectors/vectors.json').vectors;

const vector = (name) => vectors.find((v) => v.name === name);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');
const MASTER = new Uint8Array(32).fill(0x40);
const FOLDER = new Uint8Array(32).fill(0x80);
const SHARE = '22750000-0000-4000-8000-0000000000a1';
const SHARE_B = '22750000-0000-4000-8000-0000000000a2';
const ROOT = '22750000-0000-4000-8000-0000000000b1';
const ROOT_B = '22750000-0000-4000-8000-0000000000b2';

test('the label and actor-name vectors open', () => {
  const label = vector('link_label_v1');
  assert.equal(
    wasm.unwrapLinkLabel(bytes(label.master_key_hex), label.share_id, bytes(label.wrapped_hex)),
    label.label_nfc,
  );
  const name = vector('folder_actor_name_v1');
  assert.equal(wasm.openFolderActorName(bytes(name.folder_key_hex), name.root_id, name.envelope), name.actor_name);
});

test('the legacy child vector: a name is refused, a real key opens', () => {
  const v = vector('legacy_child_refusal_v1');
  const folder = bytes(v.folder_key_hex);
  assert.equal(wasm.openLegacyChildKey(folder, bytes(v.name_frame_hex)), undefined);
  assert.equal(hex(wasm.openLegacyChildKey(folder, bytes(v.child_frame_hex))), v.child_key_hex);
});

test('labels round-trip, normalize to NFC and stay bound to the share', () => {
  const wrapped = wasm.wrapLinkLabel(MASTER, SHARE, 'Cafe\u0301 photos');
  assert.equal(wasm.unwrapLinkLabel(MASTER, SHARE, wrapped), 'Café photos');
  assert.throws(() => wasm.unwrapLinkLabel(MASTER, SHARE_B, wrapped), /decryption failed/);
  assert.throws(() => wasm.unwrapLinkLabel(new Uint8Array(32).fill(0x41), SHARE, wrapped), /decryption failed/);
  // Purpose separation: a real label frame is not an owner wrap, a token, a
  // custody record or an actor name. Every row feeds this test's own writer
  // output; none hands a placeholder to the opener.
  assert.throws(() => wasm.unwrapLinkOwnerKey(MASTER, SHARE, wrapped), /decryption failed/);
  assert.throws(() => wasm.unwrapLinkOwnerToken(MASTER, SHARE, wrapped), /decryption failed/);
  // A custody record is a 60-byte frame, so use a 32-byte label: the real
  // 60-byte frame reaches the AEAD instead of the binding's length check.
  const big = wasm.wrapLinkLabel(MASTER, SHARE, '0123456789abcdef0123456789abcdef');
  assert.equal(big.length, 60);
  // Non-vacuity: these exact bytes are an openable label frame under their own
  // opener, so the refusals below are about the purpose, not malformed input.
  assert.equal(wasm.unwrapLinkLabel(MASTER, SHARE, big), '0123456789abcdef0123456789abcdef');
  assert.throws(() => wasm.unwrapFolderCustody(MASTER, SHARE, big), /decryption failed/);
  // The name writer's envelope, built from the real frame, under the same
  // 16 id bytes: the actor-name opener must refuse it at the AEAD.
  const envelopeFromLabel = JSON.stringify({
    cipher_suite: 'V1Aes256Gcm',
    nonce: Array.from(big.slice(0, 12)),
    ciphertext: Array.from(big.slice(12)),
  });
  assert.throws(() => wasm.openFolderActorName(FOLDER, SHARE, envelopeFromLabel), /decryption failed/);
  // The bound is enforced before sealing.
  assert.throws(() => wasm.wrapLinkLabel(MASTER, SHARE, 'x'.repeat(41)), /1 to 40/);
});

test('actor names round-trip, strip bidi and stay bound to the root and key', () => {
  const envelope = wasm.sealFolderActorName(FOLDER, ROOT, 'Zo\u00eb\u202e Guest\u2066\u0007');
  assert.equal(wasm.openFolderActorName(FOLDER, ROOT, envelope), 'Zoë Guest');
  assert.throws(() => wasm.openFolderActorName(FOLDER, ROOT_B, envelope), /decryption failed/);
  assert.throws(() => wasm.openFolderActorName(new Uint8Array(32).fill(0x81), ROOT, envelope), /decryption failed/);
  // One shape: the real envelope's bytes are not a label frame (the label
  // opener refuses the actual actor-name output), and text that is not an
  // envelope is refused too.
  // Non-vacuity: the envelope opens under its own opener and root (above), so
  // the label opener refuses a real, well-formed actor name.
  assert.throws(
    () => wasm.unwrapLinkLabel(MASTER, SHARE, new Uint8Array(Buffer.from(envelope, 'utf8'))),
    /decryption failed/,
  );
  assert.throws(() => wasm.openFolderActorName(FOLDER, ROOT, 'not-an-envelope'), /decryption failed/);
  // The bound is enforced before sealing.
  assert.throws(() => wasm.sealFolderActorName(FOLDER, ROOT, 'x'.repeat(65)), /1 to 64/);
});
