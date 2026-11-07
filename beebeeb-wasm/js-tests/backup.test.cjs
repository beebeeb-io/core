'use strict';
// LD-0113: the backup rules the web client needs, through the real module.
// Every protection case of test-vectors/consolidation/backup_protect.json goes
// through backupCheckRootMutation, backupCheckAppMutation (the web's own rule,
// spec Amendment 8) and backupCheckDriveMutation (the web's own run of the
// shared vectors); backupProtectionMany is the one-crossing-per-listing root
// bit, where an unknown role is protected (review #8); any other unknown
// string throws, never passes (plan Amendment 1, item 3); backupParseManifest
// keeps unknown fields. BB_VECTOR_PATH points the test at a mutated copy for a
// red run.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const protect = require(
  process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/backup_protect.json'),
);
const device = require(path.join(__dirname, '../../test-vectors/consolidation/backup_device.json'));

const DELETE_WORDS = "Backups is a system folder and can't be deleted.";
const want = (c) => (c.expect === 'ok' ? undefined : c.expect);

nodeTest('backupCheckRootMutation: the exact words, and undefined for an ordinary row', () => {
  assert.equal(wasm.backupCheckRootMutation('backups_root', 'trash'), DELETE_WORDS);
  assert.equal(wasm.backupCheckRootMutation('backups_root', 'create'), undefined);
  assert.equal(wasm.backupCheckRootMutation(null, 'trash'), undefined);
  assert.equal(wasm.backupCheckRootMutation(undefined, 'move'), undefined);
  assert.equal(wasm.backupCheckRootMutation('', 'rename'), undefined);
});

nodeTest('backupCheckRootMutation agrees with every root case of the shared vector', () => {
  const cases = protect.cases.filter((c) => c.kind === 'root_mutation');
  assert.equal(cases.length, 19, 'the 6 x 3 matrix plus a move into the root');
  for (const c of cases) {
    assert.equal(wasm.backupCheckRootMutation(c.role, c.mutation), want(c), c.id);
  }
});

nodeTest('backupCheckAppMutation and backupCheckDriveMutation agree with every case of the shared vector', () => {
  const app = protect.cases.filter((c) => c.kind === 'app_mutation');
  assert.equal(app.length, 36, '6 positions x 6 mutations');
  for (const c of app) {
    assert.equal(wasm.backupCheckAppMutation(c.position, c.mutation), want(c), c.id);
  }
  const drive = protect.cases.filter((c) => c.kind === 'drive_mutation');
  assert.equal(drive.length, 43, '6 positions x 6 mutations, 6 own active, 1 precedence');
  for (const c of drive) {
    assert.equal(wasm.backupCheckDriveMutation(c.position, c.own_active_source, c.mutation), want(c), c.id);
  }
  assert.throws(() => wasm.backupCheckDriveMutation('inside', null, 'erase'), /unknown mutation/);
  assert.throws(() => wasm.backupCheckAppMutation('under_root', 'write'), /unknown backup position/);
  assert.throws(() => wasm.backupCheckDriveMutation('Inside', null, 'write'), /unknown backup position/);
});

nodeTest('backupPositionAtDepth, backupIsHiddenItem and backupRootBadge agree with the shared vector', () => {
  const positions = protect.cases.filter((c) => c.kind === 'position');
  assert.equal(positions.length, 11, '11 positions by depth and name');
  for (const c of positions) {
    assert.equal(wasm.backupPositionAtDepth(c.depth, c.name), c.expected, c.id);
    assert.equal(wasm.backupIsHiddenItem(c.depth, c.name), c.hidden, c.id);
  }
  assert.equal(wasm.backupPositionAtDepth(undefined, 'Pictures'), 'outside');
  const names = protect.cases.find((c) => c.kind === 'names');
  assert.equal(wasm.backupRootBadge(), names.badge);
});

nodeTest('backupProtectionMany: one crossing per listing, 1 = protected', () => {
  assert.deepEqual(Array.from(wasm.backupProtectionMany(['backups_root', '', ''])), [1, 0, 0]);
  assert.ok(wasm.backupProtectionMany([]) instanceof Uint8Array);
  assert.equal(wasm.backupProtectionMany([]).length, 0);
});

nodeTest('an unknown mutation or role throws, never passes', () => {
  for (const bad of ['Trash', 'erase', '', 'delete ']) {
    assert.throws(() => wasm.backupCheckRootMutation('backups_root', bad), /unknown mutation/, bad);
    assert.throws(() => wasm.backupCheckRootMutation(null, bad), /unknown mutation/, bad);
    assert.throws(() => wasm.backupCheckAppMutation('inside', bad), /unknown mutation/, bad);
  }
  assert.throws(() => wasm.backupCheckRootMutation('Backups', 'trash'), /unknown system role/);
  // A role this bundle does not know is protected, and the listing still renders.
  assert.deepEqual(Array.from(wasm.backupProtectionMany(['backups_root', 'photos_root', '', 'Backups'])), [1, 1, 0, 1]);
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

// LD-0121: why a backup stops and its words (spec Amendment 12), the web's own run of every stop, notice and words
// case of test-vectors/consolidation/backup_plan.json (BB_PLAN_VECTOR_PATH points at a mutated copy for a red run).
const plan = require(
  process.env.BB_PLAN_VECTOR_PATH || path.join(__dirname, '../../test-vectors/consolidation/backup_plan.json'),
);

nodeTest('backupStop agrees with every stop case of the shared vector', () => {
  const cases = plan.cases.filter((c) => c.kind === 'stop');
  assert.equal(cases.length, 22, 'the six cases Amendment 12 names and sixteen more');
  for (const c of cases) {
    assert.deepEqual(wasm.backupStop(c.notices, c.last_pass_at_ms, c.listing), c.expect, c.id);
  }
});

nodeTest('backupNoticeReason, backupStopWords and backupAgainAction agree with the shared vector', () => {
  const notices = plan.cases.filter((c) => c.kind === 'notice');
  assert.equal(notices.length, 10);
  for (const c of notices) {
    assert.equal(wasm.backupNoticeReason(c.type, c.data), c.expect === null ? undefined : c.expect.reason, c.id);
  }
  const words = plan.cases.filter((c) => c.kind === 'stop_words');
  assert.equal(words.length, 7, 'one line per reason');
  for (const c of words) {
    assert.equal(wasm.backupStopWords(c.reason, c.device, c.folder), c.expect, c.id);
  }
  assert.equal(wasm.backupAgainAction(), plan.cases.find((c) => c.kind === 'stop_action').expect);
});

nodeTest('backupStop and backupStopWords throw on what they do not know', () => {
  const listing = { device_folder_id: 'GLegion', device_folder_live: true, folders: [] };
  assert.throws(() => wasm.backupStop([], 0, listing), /device_folder_id is not a UUID/);
  const dev = '00000064-0000-4000-8000-0000000000aa';
  const bad = { device_folder_id: dev, device_folder_live: true, folders: [{ category: 'Pictures' }] };
  assert.throws(() => wasm.backupStop([], 0, bad), /unknown category key/);
  assert.throws(() => wasm.backupStop([], 1.5, { ...listing, device_folder_id: dev }), /lastPassAtMs/);
  for (const reason of ['Unknown', 'erased_request', '']) {
    assert.throws(() => wasm.backupStopWords(reason, 'GLegion', 'Pictures'), /unknown backup stop reason/, reason);
  }
});

nodeTest('backupStop skips rows that are not backup notices, whatever their shape', () => {
  const dev = '00000064-0000-4000-8000-0000000000aa';
  const pics = '00000065-0000-4000-8000-0000000000aa';
  const listing = {
    device_folder_id: dev,
    device_folder_live: true,
    folders: [{ category: 'pictures', category_folder_id: pics, category_folder_live: true }],
  };
  const erased = { type: 'files_removed', data: { reason: 'erase_request' }, created_at_ms: 1762430400001 };
  const odd = [{ type: 'share_received' }, { data: {} }, { type: 'share_received', created_at_ms: 'yesterday' }, null];
  assert.deepEqual(wasm.backupStop([...odd, erased], 1762430400000, listing), [
    { category: 'pictures', reason: 'erase_request' },
  ]);
  for (const created_at_ms of [undefined, null, 1.5, '2026-11-06T21:30:00Z']) {
    const row = { type: 'files_removed', data: { reason: 'erase_request' }, created_at_ms };
    assert.throws(() => wasm.backupStop([row], 0, listing), /no whole created_at_ms/, String(created_at_ms));
  }
});
