'use strict';
// Crypto review, P2-4: the content decryptor takes the object
// decrypt_file_metadata returned, so the version commitment in it is enforced:
// the server cannot serve another complete upload of the same file in place
// of the recorded version.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);

const MK = new Uint8Array(32).fill(5);
const FILE_ID = 'js-replay-file';
const DATA = Uint8Array.from({ length: 40 }, (_, i) => i);

function upload() {
  const enc = wasm.WasmChunkEncryptor.withChunkSize(MK, FILE_ID, BigInt(DATA.length), 16n);
  const frames = [];
  for (let at = 0; at < DATA.length; at += 16) frames.push(enc.pushChunk(DATA.subarray(at, at + 16)));
  const version = enc.versionCommitment(undefined);
  enc.finish();
  return { frames, version };
}

function read(metadata, frames) {
  const dec = new wasm.WasmChunkDecryptor(MK, FILE_ID, metadata);
  const out = [];
  for (const frame of frames) out.push(...dec.pushFrame(frame));
  dec.finish();
  return Uint8Array.from(out);
}

nodeTest('the decryptor enforces the commitment in decrypt_file_metadata', () => {
  const older = upload();
  const current = upload();
  const sealed = wasm.encrypt_name_with_version(
    MK, FILE_ID, 'a.txt', undefined, 2, current.version.versionId, current.version.versionCounter,
  );
  const metadata = wasm.decrypt_file_metadata(MK, FILE_ID, sealed);
  assert.equal(metadata.chunk_format, 2);
  assert.equal(metadata.version_counter, 1);

  assert.deepEqual(read(metadata, current.frames), DATA);
  assert.throws(() => read(metadata, older.frames), 'an older upload must not open under this record');
});

nodeTest('a missing record or half a commitment is refused', () => {
  const { frames } = upload();
  assert.throws(() => new wasm.WasmChunkDecryptor(MK, FILE_ID, undefined), /metadata is required/);
  assert.throws(() => new wasm.WasmChunkDecryptor(MK, FILE_ID, 2), /decrypt_file_metadata/);
  assert.throws(
    () => new wasm.WasmChunkDecryptor(MK, FILE_ID, { chunk_format: 2, version_id: '00112233445566778899aabb' }),
    /together/,
  );
});

// Guus's ruling of 2026-11-07, "refuse v2 without commitment": a record with no
// version commitment opens no v2 content, through the decryptor or the
// random-access open.
nodeTest('a record without a commitment opens no v2 content', () => {
  const { frames, version } = upload();
  assert.throws(() => new wasm.WasmChunkDecryptor(MK, FILE_ID, { chunk_format: 2 }), /without a version commitment/);
  assert.throws(() => read({ chunk_format: 0 }, frames), 'an unrecorded record without a commitment opened v2');

  const fileKey = wasm.derive_file_key(MK, new TextEncoder().encode(FILE_ID));
  const last = frames.length - 1;
  const committed = {
    chunk_format: 2,
    version_id: Buffer.from(version.versionId).toString('hex'),
    version_counter: version.versionCounter,
  };
  assert.deepEqual(
    wasm.decrypt_chunk_frame(fileKey, FILE_ID, committed, last, true, frames[last]),
    DATA.subarray(16 * last),
  );
  for (const bare of [{ chunk_format: 2 }, { chunk_format: 0 }]) {
    assert.throws(() => wasm.decrypt_chunk_frame(fileKey, FILE_ID, bare, last, true, frames[last]));
  }
});
