'use strict';
// C3 move 9's WASM surface: one share-link grammar. Every case in
// test-vectors/consolidation/share_link.json goes through a wasm export —
// build on both routes (including each route's existing encoding), parse on
// both routes and on legacy hosts, the four stable error codes, and the key
// decoder for both base64 alphabets.
// BB_VECTOR_PATH points the same test at a mutated copy for the red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/share_link.json'));

const hex = (bytes) => (bytes === null || bytes === undefined ? null : Buffer.from(bytes).toString('hex'));

nodeTest('the share-link vector: build, parse, the error codes and key bytes agree with every case', () => {
  assert.equal(vectors.cases.length, 29, 'every case in share_link.json is exercised');

  for (const c of vectors.cases) {
    if (c.kind === 'build') {
      assert.equal(wasm.buildShareLink(c.app_url, c.token, c.key, c.route), c.expected, c.id);
    } else if (c.kind === 'parse') {
      const got = wasm.parseShareLink(c.url);
      assert.equal(got.base_url, c.expected.base_url, `${c.id}: base_url`);
      assert.equal(got.route, c.expected.route, `${c.id}: route`);
      assert.equal(got.token, c.expected.token, `${c.id}: token`);
      assert.equal(got.key, c.expected.key, `${c.id}: key`);
      if (c.expected.key_hex) {
        assert.equal(hex(wasm.shareKeyBytes(got.key)), c.expected.key_hex, `${c.id}: key_hex`);
      }
    } else if (c.kind === 'parse-error') {
      assert.throws(
        () => wasm.parseShareLink(c.url),
        (error) => error.message.startsWith(c.expected),
        c.id,
      );
    } else if (c.kind === 'key-bytes') {
      assert.equal(hex(wasm.shareKeyBytes(c.key)), c.expected, c.id);
    } else {
      assert.fail(`${c.id}: unknown vector kind ${c.kind}`);
    }
  }
});

nodeTest('build keeps each route encoding, and a link parses back to what built it', () => {
  const token = 'AAECAwQFBgcICQoLDA0ODxAREhM';
  const key = '-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s';

  // Without a route the builder mints the canonical `/s/` link; `"f"` is the
  // folder route, and its base64url key is left byte-identical.
  assert.equal(
    wasm.buildShareLink('https://app.beebeeb.io', token, key),
    `https://app.beebeeb.io/s/${token}#key=${key}`,
  );
  assert.equal(
    wasm.buildShareLink('https://app.beebeeb.io', token, key, 'f'),
    `https://app.beebeeb.io/f/${token}#key=${key}`,
  );

  const parsed = wasm.parseShareLink(wasm.buildShareLink('https://app.beebeeb.io', token, key, 'f'));
  assert.deepEqual(parsed, { base_url: 'https://app.beebeeb.io', route: 'f', token, key });

  // A route that is neither `s` nor `f` is refused rather than guessed.
  assert.throws(() => wasm.buildShareLink('https://app.beebeeb.io', token, key, 'x'), /unknown share route/);
});

nodeTest('both live encodings survive one round trip: raw #key on /s/ and base64url on /f/', () => {
  // Mobile's constraint: `/s/` links may carry a raw (unencoded) standard
  // base64 key, `/f/` links carry base64url. Parsing accepts both, and neither
  // is rewritten.
  const raw = wasm.parseShareLink('https://app.beebeeb.io/s/AAECAwQFBgcICQoLDA0ODxAREhM#key=+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=');
  assert.equal(raw.key, '+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=');
  assert.equal(hex(wasm.shareKeyBytes(raw.key)), 'fb'.repeat(32));

  const b64url = wasm.parseShareLink('https://app.beebeeb.io/f/AAECAwQFBgcICQoLDA0ODxAREhM#key=-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s');
  assert.equal(b64url.key, '-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s');
  assert.equal(hex(wasm.shareKeyBytes(b64url.key)), 'fb'.repeat(32));
});