'use strict';
// C3 move 2's WASM surface: the JSON metadata envelope in both directions.
// Every case in test-vectors/consolidation/envelope.json goes through the
// export — the stored forms a client may hand us, and the one canonical writer.
// BB_VECTOR_PATH points the same test at a mutated copy for the red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/envelope.json'));
const hex = (b) => Buffer.from(b).toString('hex');

nodeTest('the envelope vector: every stored form decodes and the writer is unchanged', () => {
  assert.equal(vectors.cases.length, 15, 'every case in envelope.json is exercised');

  for (const c of vectors.cases) {
    if (c.kind === 'decode') {
      const envelope = wasm.decodeMetadataEnvelope(c.payload);
      assert.equal(envelope.cipher_suite, c.expected.cipher_suite, `${c.id}: cipher_suite`);
      assert.equal(hex(envelope.nonce), c.expected.nonce_hex, `${c.id}: nonce`);
      assert.equal(hex(envelope.ciphertext), c.expected.ciphertext_hex, `${c.id}: ciphertext`);
    } else if (c.kind === 'decode-error') {
      assert.throws(
        () => wasm.decodeMetadataEnvelope(c.payload),
        (e) => e.message.startsWith('invalid input:'),
        `${c.id}: refused as ${c.expected_error}`,
      );
    } else if (c.kind === 'encode-error') {
      // A nonce that is not 12 bytes is refused before any bytes are written.
      assert.throws(
        () =>
          wasm.encodeMetadataEnvelope(
            Buffer.from(c.nonce_hex, 'hex'),
            Buffer.from(c.ciphertext_hex, 'hex'),
          ),
        (e) => e.message.startsWith('invalid input:') && e.message.includes(c.expect),
        `${c.id}: refused as ${c.expect}`,
      );
    } else if (c.kind === 'encode') {
      // The encode cases carry an optional `cipher_suite`; the writer ignores
      // it on purpose, so both cases must produce the same canonical bytes.
      const written = wasm.encodeMetadataEnvelope(
        Buffer.from(c.nonce_hex, 'hex'),
        Buffer.from(c.ciphertext_hex, 'hex'),
      );
      assert.equal(written, c.expected_canonical, `${c.id}: canonical writer`);
    } else {
      assert.fail(`${c.id}: unknown vector kind ${c.kind}`);
    }
  }
});

nodeTest('a decoded envelope re-encodes to the same canonical bytes', () => {
  const canonical = '{"ciphertext":"EBESExQVFhcYGRobHB0eHw==","nonce":"AAECAwQFBgcICQoL"}';
  const envelope = wasm.decodeMetadataEnvelope(canonical);
  assert.equal(wasm.encodeMetadataEnvelope(envelope.nonce, envelope.ciphertext), canonical);
});
