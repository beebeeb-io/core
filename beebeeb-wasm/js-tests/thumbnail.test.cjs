'use strict';
// C3 move 12's WASM surface: the thumbnail policy as data. Every exportable case
// in test-vectors/consolidation/thumbnail.json goes through a wasm export — the
// ladder and budgets per variant, the per-platform format rule and the budget
// verdict. The four resize cases stay with the encoder (native or the browser's
// canvas), so they are named below and must stay unexported.
// BB_VECTOR_PATH points the same test at a mutated copy for the red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/thumbnail.json'));

// The encoder-side cases: a policy is data, the resize is the platform's job.
const RESIZE_ONLY = [
  'thumb_resize_source_smaller',
  'thumb_resize_landscape',
  'thumb_zero_dimension',
  'thumb_resize_tiny_target',
];

nodeTest('the thumbnail vector: ladder, format and budget agree with every case', () => {
  assert.equal(vectors.cases.length, 23, 'every case in thumbnail.json is accounted for');

  const skipped = [];
  for (const c of vectors.cases) {
    if (RESIZE_ONLY.includes(c.id)) {
      skipped.push(c.id);
      continue;
    }

    if (c.kind === 'ladder') {
      const got = wasm.thumbnailPolicy(c.variant);
      assert.equal(got.variant, c.variant, `${c.id}: variant`);
      assert.equal(got.target_px, c.target_px, `${c.id}: target_px`);
      assert.equal(got.target_bytes, c.target_bytes, `${c.id}: target_bytes`);
      assert.equal(got.max_bytes, c.max_bytes, `${c.id}: max_bytes`);
      assert.equal(got.steps.length, c.steps.length, `${c.id}: step count`);
      c.steps.forEach((step, index) => {
        assert.equal(got.steps[index].max_dimension, step.max_dimension, `${c.id}: step ${index} max_dimension`);
        assert.equal(got.steps[index].quality, step.quality, `${c.id}: step ${index} quality`);
      });
    } else if (c.kind === 'format') {
      assert.equal(wasm.thumbnailFormat(c.variant, c.platform), c.expected, c.id);
    } else if (c.kind === 'budget') {
      assert.equal(wasm.thumbnailBudget(c.variant, c.bytes), c.expected, c.id);
    } else {
      assert.fail(`${c.id}: unknown vector kind ${c.kind}`);
    }
  }

  assert.deepEqual(skipped.sort(), [...RESIZE_ONLY].sort(), 'the resize cases are exactly the four named ones');
});

nodeTest('the three variants are the shipped ones, and nothing is guessed', () => {
  // Large is the full-screen budget the plan names: 1600 px, six steps, 400 KiB
  // target under the 480 KiB server cap.
  const large = wasm.thumbnailPolicy('large');
  assert.equal(large.target_px, 1600);
  assert.equal(large.steps.length, 6);
  assert.equal(large.target_bytes, 409600);
  assert.equal(large.max_bytes, 491520);

  // The budget boundaries are inclusive at target and at max.
  assert.equal(wasm.thumbnailBudget('large', 409600), 'target');
  assert.equal(wasm.thumbnailBudget('large', 409601), 'fallback');
  assert.equal(wasm.thumbnailBudget('large', 491520), 'fallback');
  assert.equal(wasm.thumbnailBudget('large', 491521), 'rejected');

  // An unknown variant or platform is refused rather than defaulted.
  assert.throws(() => wasm.thumbnailPolicy('huge'), /unknown thumbnail variant/);
  assert.throws(() => wasm.thumbnailFormat('medium', 'amiga'), /unknown platform/);
});