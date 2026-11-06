'use strict';
// LD-0113: the backup rules the web client needs, through the real module.
// The protection cases of test-vectors/consolidation/backup_protect.json go
// through backupCheckMutation (the web's own run of the shared vectors);
// backupProtectionMany is the one-crossing-per-listing form; an unknown string
// throws, never passes (plan Amendment 1, item 3); backupParseManifest keeps
// unknown fields. BB_VECTOR_PATH points the test at a mutated copy for a red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const protect = require(
  process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/backup_protect.json'),
);
const device = require(path.join(__dirname, '../../test-vectors/consolidation/backup_device.json'));

const DELETE_WORDS = "Backups is a system folder and can't be deleted.";

nodeTest('backupCheckMutation: the exact words, and undefined for an ordinary row', () => {
  assert.equal(wasm.backupCheckMutation('backups_root', 'trash'), DELETE_WORDS);
  assert.equal(wasm.backupCheckMutation(null, 'trash'), undefined);
  assert.equal(wasm.backupCheckMutation(undefined, 'move'), undefined);
  assert.equal(wasm.backupCheckMutation('', 'rename'), undefined);
});

nodeTest('backupCheckMutation agrees with every mutation case of the shared vector', () => {
  const cases = protect.cases.filter((c) => c.kind === 'mutation');
  assert.equal(cases.length, 13, 'the 4 x 3 matrix plus a move into the root');
  for (const c of cases) {
    const got = wasm.backupCheckMutation(c.role, c.mutation);
    assert.equal(got, c.expect === 'ok' ? undefined : c.expect, c.id);
  }
});

nodeTest('backupProtectionMany: one crossing per listing, 1 = protected', () => {
  assert.deepEqual(Array.from(wasm.backupProtectionMany(['backups_root', '', ''])), [1, 0, 0]);
  assert.ok(wasm.backupProtectionMany([]) instanceof Uint8Array);
  assert.equal(wasm.backupProtectionMany([]).length, 0);
});

nodeTest('an unknown mutation or role throws, never passes', () => {
  for (const bad of ['Trash', 'erase', '', 'delete ']) {
    assert.throws(() => wasm.backupCheckMutation('backups_root', bad), /unknown mutation/, bad);
    assert.throws(() => wasm.backupCheckMutation(null, bad), /unknown mutation/, bad);
  }
  assert.throws(() => wasm.backupCheckMutation('Backups', 'trash'), /unknown system role/);
  assert.throws(() => wasm.backupProtectionMany(['backups_root', 'Backups']), /unknown system role/);
});

nodeTest('backupParseManifest: the real iOS manifest and unknown fields come back as a plain object', () => {
  const ios = device.cases.find((c) => c.id === 'manifest_real_ios_round_trips');
  const parsed = wasm.backupParseManifest(ios.json);
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype, 'a plain object, not a Map');
  assert.equal(parsed.device_name, 'Example iPhone');
  assert.equal(parsed.device_model, 'iPhone 17 Pro');
  assert.equal(parsed.backups.camera_roll.items_synced, 4210);
  assert.equal(parsed.platform, undefined);

  const future = device.cases.find((c) => c.id === 'manifest_unknown_field_is_kept');
  const kept = wasm.backupParseManifest(future.json);
  assert.deepEqual(kept.a_future_field, { nested: [1, 2, 3], flag: true });
  assert.equal(kept.platform, 'windows');

  assert.throws(() => wasm.backupParseManifest('[1, 2]'), /device manifest/);
});
