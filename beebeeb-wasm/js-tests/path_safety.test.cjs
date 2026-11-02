'use strict';
// C3 move 11's WASM surface: the pure naming rules. Every exportable case in
// test-vectors/consolidation/path_safety.json goes through a wasm export —
// `checkPathComponent` for both rule sets, `sanitizePathComponent` and
// `archiveEntryName` for the archive rewrite. The six native-only cases
// (rel-join and symlink containment) are named below and must stay
// unexported: a browser has no local filesystem to contain.
// BB_VECTOR_PATH points the same test at a mutated copy for the red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/path_safety.json'));

// The cases that cannot leave the native side, exactly.
const NATIVE_ONLY = [
  'path_rel_join_ok',
  'path_rel_join_empty_segment',
  'path_rel_join_dotdot',
  'path_rel_join_long',
  'path_ensure_contained_ok',
  'path_ensure_contained_escape',
];

nodeTest('the path-safety vector: check, sanitize and the archive rule agree with every case', () => {
  assert.equal(vectors.cases.length, 52, 'every case in path_safety.json is accounted for');

  const skipped = [];
  for (const c of vectors.cases) {
    if (NATIVE_ONLY.includes(c.id)) {
      skipped.push(c.id);
      continue;
    }

    if (c.kind === 'check') {
      if (c.expect === 'ok') {
        assert.doesNotThrow(() => wasm.checkPathComponent(c.name, c.portable, c.windows), c.id);
      } else {
        assert.throws(
          () => wasm.checkPathComponent(c.name, c.portable, c.windows),
          (error) => error.message === c.reason || error.message.includes(c.reason || ''),
          c.id,
        );
      }
    } else if (c.kind === 'sanitize') {
      if (c.expect === 'ok') {
        assert.equal(wasm.sanitizePathComponent(c.name), c.expected, c.id);
        // The archive entry is the same portable rewrite.
        assert.equal(wasm.archiveEntryName(c.name), c.expected, `${c.id}: archive`);
      } else {
        assert.throws(() => wasm.sanitizePathComponent(c.name), (error) => error.message.includes(c.reason || ''), c.id);
        assert.throws(() => wasm.archiveEntryName(c.name), (error) => error.message.includes(c.reason || ''), c.id);
      }
    } else {
      assert.fail(`${c.id}: unknown vector kind ${c.kind}`);
    }
  }

  assert.deepEqual(skipped.sort(), [...NATIVE_ONLY].sort(), 'the native-only cases are exactly the six named ones');
});

nodeTest('the native-only half is not exported, and the rule sets stay distinct', () => {
  // The filesystem part is native-only in core; it must not have leaked in.
  assert.equal(typeof wasm.safeRelJoin, 'undefined');
  assert.equal(typeof wasm.ensureContained, 'undefined');
  assert.equal(typeof wasm.safeChild, 'undefined');

  // A backslash is a separator only when the portable or Windows rule says so:
  // a Linux host keeps `a\b` (sync must not look like a remote delete).
  assert.doesNotThrow(() => wasm.checkPathComponent('a\\b', false, false));
  assert.throws(() => wasm.checkPathComponent('a\\b', true, false), /path separator/);
  assert.throws(() => wasm.checkPathComponent('a\\b', false, true), /path separator/);

  // The sanitizer never silently drops: a `..` name is refused, not rewritten.
  assert.throws(() => wasm.archiveEntryName('..'), /'\.' and '\.\.'/);
});