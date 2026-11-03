'use strict';
// C3 move 3's per-platform preview table, through the WASM surface.
// `previewableBatchFor(names, platform)` is the additive export: every case in
// test-vectors/consolidation/preview_platforms.json must agree for each of the
// three columns, an unknown platform must throw (never default), and the 18
// types web lost in the consolidation must be back.
// BB_VECTOR_PATH points the same test at a mutated copy for the red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(
  process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/preview_platforms.json'),
);

// The 18 types web rendered before the consolidation switch changed its list.
const RESTORED = [
  'aif', 'aiff', 'alac', 'arw', 'cr2', 'cr3', 'dng', 'hevc', 'key', 'nef', 'oga', 'orf', 'ppt', 'raf', 'rw2', 'tsv',
  'xls', 'zip',
];

nodeTest('the preview-platform vector: every row, every column, through one export', () => {
  assert.equal(vectors.cases.length, vectors.counts.union + 8, 'every union row plus the shape cases');
  assert.equal(RESTORED.length, 18, 'web lost 18 types');

  for (const platform of ['web', 'desktop', 'mobile']) {
    for (const c of vectors.cases) {
      const expected = c.expected[platform] ? 1 : 0;
      const got = wasm.previewableBatchFor([c.name], platform);
      assert.equal(got.length, 1, `${c.id}: one bit per name`);
      assert.equal(got[0], expected, `${c.id}: \`${c.name}\` on ${platform}`);
    }
  }

  // The 18 restored types are previewable on the web column again.
  for (const ext of RESTORED) {
    assert.ok(
      vectors.cases.some((c) => c.extension === ext && c.expected.web === true),
      `${ext} is a web type web must get back`,
    );
    assert.equal(wasm.previewableBatchFor([`file.${ext}`], 'web')[0], 1, `${ext} on web`);
  }

  // Whole-list calls: order is preserved, empty is empty.
  for (const b of vectors.batches) {
    assert.deepEqual(Array.from(wasm.previewableBatchFor(b.names, b.platform)), b.expected.map(Number), b.id);
  }
  for (const platform of ['web', 'desktop', 'mobile']) {
    assert.equal(wasm.previewableBatchFor([], platform).length, 0, `${platform}: empty in, empty out`);
  }

  // An unknown platform is an error, never a default answer.
  for (const unknown of ['', 'Web', 'ios', 'android', 'mobile ']) {
    assert.throws(
      () => wasm.previewableBatchFor(['file.jpg'], unknown),
      (error) => error.message.includes('unknown preview platform'),
      `\`${unknown}\` must not resolve to a platform`,
    );
  }
  assert.equal(wasm.previewableBatchFor(['file.jpg'], 'mobile')[0], 1, 'the platform name is case-sensitive');
  assert.equal(wasm.previewableBatchFor(['file.dng'], 'desktop')[0], 1, 'a desktop raw type');
  assert.equal(wasm.previewableBatchFor(['file.dng'], 'mobile')[0], 0, 'a mobile raw type');
});
