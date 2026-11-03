'use strict';
// C3 move 6's WASM surface: the one retry policy. Every case in
// test-vectors/consolidation/retry.json goes through a wasm export — the
// ladder, deterministic full jitter, the per-outcome decision, the budget
// boundary and the Retry-After parser.
// BB_VECTOR_PATH points the same test at a mutated copy for the red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/retry.json'));

// A policy is a plain object; `null` means the shipped default.
const policy = (over = {}) => ({ ...wasm.retryPolicy(), ...over });
// A decision or a parsed header is a number or `null`.
const ms = (value) => (value === null || value === undefined ? null : value);

nodeTest('the retry vector: ladder, jitter, decision and parse agree with every case', () => {
  assert.equal(vectors.cases.length, 30, 'every case in retry.json is exercised');

  for (const c of vectors.cases) {
    let got;
    let expected;
    if (c.kind === 'ladder') {
      got = wasm.retryDelayMs(null, c.retry);
      expected = c.expected_ms;
    } else if (c.kind === 'jitter') {
      got = wasm.retryJitteredDelayMs(policy({ jitter: c.jitter }), c.retry, c.sample_permille);
      expected = c.expected_ms;
    } else if (c.kind === 'decision') {
      got = ms(wasm.retryDecide(null, c.attempts_made, c.outcome, c.retry_after_seconds));
      expected = c.expected_ms;
    } else if (c.kind === 'parse') {
      got = ms(wasm.parseRetryAfter(c.value));
      expected = c.expected_seconds;
    } else {
      assert.fail(`${c.id}: unknown vector kind ${c.kind}`);
    }
    assert.equal(got, expected, c.id);
  }
});

nodeTest('the exported policy is the one web needs, and its fields are read back', () => {
  assert.deepEqual(policy(), { max_attempts: 6, base_ms: 500, cap_ms: 30000, jitter: 'none' });

  // The cap replaces the doubling ladder rather than extending it.
  assert.equal(wasm.retryDelayMs(policy({ cap_ms: 1000 }), 4), 1000);
  // A shorter budget stops the decision at its own boundary.
  assert.equal(ms(wasm.retryDecide(policy({ max_attempts: 2 }), 2, { status: 503 }, null)), null);
  assert.equal(ms(wasm.retryDecide(policy({ max_attempts: 2 }), 1, { status: 503 }, null)), 500);
  // A stated Retry-After wins over the ladder, including on a 429.
  assert.equal(ms(wasm.retryDecide(null, 1, { status: 429 }, 12)), 12000);
  // An unknown jitter is refused instead of silently defaulting.
  assert.throws(() => wasm.retryDelayMs(policy({ jitter: 'partial' }), 1), /unknown retry jitter/);
});