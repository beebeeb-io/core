'use strict';
// The archive reader, preview model, planner and extraction engine through the
// real module, the way the web drives them: a push session that asks for byte
// ranges and is supplied them. Every fixture and every word of
// test-vectors/archives_v1.json goes through wasm, one test each, so the run's
// count is the vectors' count plus the surface tests below. BB_VECTOR_PATH
// points the test at a mutated copy for a red run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const nodeTest = require('node:test');
const path = require('node:path');
const wasm = require(process.env.BB_WASM_PKG);

const vectors = require(process.env.BB_VECTOR_PATH || path.join(__dirname, '../../test-vectors/archives_v1.json'));
const fixtureDir = path.join(__dirname, '../../test-vectors/archives');
const fixture = (file) => new Uint8Array(fs.readFileSync(path.join(fixtureDir, file)));
// Public test password of the 7-Zip and Info-ZIP fixtures (make_archive_password_fixtures.sh).
const TEST_PASSWORD = 'beebeeb-test-password';
const SECRET = 'The protected test file.\n'.repeat(40);

// Answer every byte range the session or extraction asks for, until it says something else.
function drive(target, bytes) {
  for (let turn = 0; turn < 10000; turn++) {
    const step = target.step();
    if (step.kind !== 'need_bytes') return step;
    assert.equal(typeof step.start, 'bigint');
    target.supply(step.start, bytes.subarray(Number(step.start), Number(step.end)));
  }
  throw new Error('the session never stopped asking for bytes');
}

function open(file, platform = vectors.platform) {
  const bytes = fixture(file);
  const session = new wasm.WasmArchiveSession(BigInt(bytes.length), platform);
  return { session, bytes, step: drive(session, bytes) };
}

// An entry in the vectors' own shape.
function row(entry) {
  const cipher = entry.cipher.kind === 'aes' ? `aes${entry.cipher.bits}_ae${entry.cipher.ae}` : entry.cipher.kind;
  const skip = entry.skip === null ? null : entry.skip.detail ? `${entry.skip.reason}:${entry.skip.detail}` : entry.skip.reason;
  assert.equal(typeof entry.size, 'bigint');
  return {
    display_path: entry.display_path,
    path: entry.path,
    kind: entry.kind,
    size: entry.size.toString(),
    cipher,
    skip,
  };
}

for (const want of vectors.fixtures) {
  nodeTest(`fixture ${want.file} lists as recorded`, () => {
    const { session, step } = open(want.file);
    if (want.refusal === null) {
      assert.equal(step.kind, 'listed', want.file);
      const listing = session.listing();
      assert.equal(listing.format, want.format);
      assert.equal(listing.complete, true);
      assert.deepEqual(listing.entries.map(row), want.entries);
    } else {
      assert.equal(step.kind, 'refused', want.file);
      assert.equal(step.format ? `${step.refusal}:${step.format}` : step.refusal, want.refusal);
      assert.equal(typeof step.text.text, 'string');
    }
  });
}

for (const want of vectors.words) {
  nodeTest(`word ${want.key} ${JSON.stringify(want.args)}`, () => {
    const got = wasm.archiveText(want.key, want.args);
    assert.equal(got.key, want.key);
    assert.equal(got.text, want.text);
    assert.deepEqual(got.args, want.args);
  });
}

for (const want of vectors.counts) {
  nodeTest(`count ${want.value}`, () => {
    assert.equal(wasm.archiveCountLabel(BigInt(want.value)), want.text);
  });
}

for (const want of vectors.sizes) {
  nodeTest(`size ${want.bytes}`, () => {
    assert.equal(wasm.archiveSizeLabel(BigInt(want.bytes)), want.text);
  });
}

nodeTest('2^53 + 1 crosses as a bigint, exactly', () => {
  const len = 2n ** 53n + 1n;
  const session = new wasm.WasmArchiveSession(len, 'browser');
  assert.deepEqual(session.step(), { kind: 'need_bytes', start: 0n, end: 512n });
  const head = new Uint8Array(512);
  head.set([0x50, 0x4b, 0x03, 0x04]); // a zip's first local header: the session asks for the tail
  session.supply(0n, head);
  const tail = session.step();
  assert.equal(tail.kind, 'need_bytes');
  assert.equal(typeof tail.start, 'bigint');
  assert.equal(tail.end, len);
  assert.equal(tail.start, len - 65_633n);
});

nodeTest('preview, plan and extraction over plain.zip', () => {
  const { session, bytes, step } = open('plain.zip', 'browser');
  assert.equal(step.kind, 'listed');
  const input = { archive_name: 'plain.zip', folder: [], selection: [], destination: 'next_to', password: null };
  const model = session.preview(input);
  assert.equal(model.state.kind, 'listed');
  assert.equal(model.summary.key, 'archive_summary');
  assert.deepEqual([model.summary.args.files, model.summary.args.folders], ['5', '3']);
  assert.deepEqual(
    model.rows.map((r) => r.name),
    ['docs', 'photos', 'empty.txt', 'notes.txt', 'story.txt'],
  );
  assert.equal(model.actions[0].kind, 'extract');

  const request = {
    archive_name: 'plain.zip',
    selection: 'all',
    destination: { siblings: ['plain', 'plain.zip'], backup_position: null, writable: true },
    server_free_bytes: 10n ** 12n,
    device_free_bytes: null,
  };
  const plan = session.plan(request);
  assert.equal(plan.kind, 'planned');
  const view = plan.view();
  assert.deepEqual(view.target, { kind: 'folder', node: 0 });
  assert.equal(view.nodes[0].name, 'plain (2)');
  assert.equal(view.totals.files, 5);
  assert.equal(typeof view.totals.bytes, 'bigint');
  const refused = session.plan({ ...request, destination: { ...request.destination, writable: false } });
  assert.deepEqual([refused.kind, refused.refusal, refused.text.key], ['refused', 'read_only_folder', 'refuse_read_only_folder']);

  const extraction = session.startExtraction({ file_id: 'archive-file', object_version_id: 'v1' }, plan, undefined);
  assert.throws(() => session.step(), /moved into an extraction/);
  const files = new Map();
  let finished = null;
  for (let turn = 0; turn < 10000 && finished === null; turn++) {
    const s = drive(extraction, bytes);
    switch (s.kind) {
      case 'create_folder':
        extraction.folderCreated(s.node, `folder-${s.node}`);
        break;
      case 'file_begin':
        files.set(s.node, { name: s.name, size: s.size, parts: [] });
        break;
      case 'file_data':
        assert.ok(s.bytes instanceof Uint8Array);
        files.get(s.node).parts.push(Buffer.from(s.bytes));
        break;
      case 'file_end':
        extraction.uploadFinished(s.node, true);
        break;
      case 'progress':
        assert.equal(s.text.key, 'extract_progress');
        assert.equal(extraction.preview(input).state.kind, 'extracting');
        break;
      case 'waiting':
        break;
      case 'finished':
        finished = s;
        break;
      default:
        assert.fail(`unexpected step ${s.kind}`);
    }
  }
  assert.deepEqual([finished.outcome, finished.files_done, finished.files_total], ['done', 5, 5]);
  assert.equal(finished.text.text, 'Extracted 5 files to "plain (2)".');
  assert.equal(extraction.preview(input).state.kind, 'finished');
  const readme = [...files.values()].find((f) => f.name === 'readme.txt');
  assert.equal(Buffer.concat(readme.parts).toString(), 'Read me.\n');
  assert.equal(readme.size, 9n);
});

nodeTest('checkPassword and openEntry over aes256.zip', () => {
  const { session, bytes, step } = open('aes256.zip', 'browser');
  assert.equal(step.kind, 'listed');
  const check = (password) => {
    for (;;) {
      const s = session.checkPassword(0, password);
      if (s.kind !== 'need_bytes') return s.kind;
      session.supply(s.start, bytes.subarray(Number(s.start), Number(s.end)));
    }
  };
  assert.equal(check('not-the-password'), 'wrong');
  assert.equal(check(TEST_PASSWORD), 'accepted');
  const read = (password) => {
    for (;;) {
      const s = session.openEntry(0, password);
      if (s.kind !== 'need_bytes') return s;
      session.supply(s.start, bytes.subarray(Number(s.start), Number(s.end)));
    }
  };
  const opened = read(TEST_PASSWORD);
  assert.equal(opened.kind, 'bytes');
  assert.equal(Buffer.from(opened.bytes).toString(), SECRET);
  assert.equal(read('not-the-password').kind, 'wrong');
  const model = session.preview({ archive_name: 'aes256.zip', folder: [], selection: [], destination: 'next_to', password: true });
  assert.deepEqual(model.state, { kind: 'needs_password', wrong: true });
});

nodeTest('an unknown platform, word, destination or reason throws, never passes', () => {
  assert.throws(() => new wasm.WasmArchiveSession(10n, 'desktop'), /unknown archive platform/);
  assert.throws(() => wasm.archiveText('archive_nope', {}), /unknown archive word/);
  const { session } = open('plain.zip');
  assert.throws(
    () => session.preview({ archive_name: 'a', folder: [], selection: [], destination: 'beside', password: null }),
    /unknown destination/,
  );
  const plan = session.plan({
    archive_name: 'plain.zip',
    selection: 'all',
    destination: { siblings: [], backup_position: null, writable: true },
    server_free_bytes: 10n ** 12n,
    device_free_bytes: null,
  });
  const extraction = session.startExtraction({ file_id: 'f', object_version_id: 'v' }, plan, undefined);
  assert.throws(() => extraction.runFailed('meteor'), /unknown fail reason/);
});
