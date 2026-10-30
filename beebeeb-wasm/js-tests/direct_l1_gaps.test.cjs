'use strict'
// The L1 gaps core now owns (task 2173 plan K1): the storage-answer check, pacing, the memory
// classes, the storage allowlist, the planner's chunk length and the response caps. Core, the
// Rust seams and these JS tests all read the same rules, so a wrapper cannot drift.
const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')

const pkg = process.env.BB_WASM_PKG
if (!pkg) throw new Error('BB_WASM_PKG must point at the wasm-pack --target nodejs output (js-tests/run.sh sets it)')
const wasm = require(path.resolve(pkg, 'beebeeb_wasm.js'))

function codeOf(fn) {
  try {
    fn()
  } catch (e) {
    return e.code
  }
  return 'did not throw'
}

function statusOf(fn) {
  try {
    fn()
  } catch (e) {
    return e.status
  }
  return 'did not throw'
}

const CHUNK = 4 * 1024 * 1024 + 28

test('checkStorageGet: only 200 with the exact length is stored', () => {
  assert.deepEqual(wasm.checkStorageGet(200, CHUNK, CHUNK), { kind: 'stored' })
  assert.deepEqual(wasm.checkStorageGet(200, CHUNK - 1, CHUNK), { kind: 'failed', status: 200 })
  assert.deepEqual(wasm.checkStorageGet(200, null, CHUNK), { kind: 'failed', status: 200 })
  assert.deepEqual(wasm.checkStorageGet(206, CHUNK, CHUNK), { kind: 'failed', status: 206 })
  assert.deepEqual(wasm.checkStorageGet(403, CHUNK, CHUNK), { kind: 'failed', status: 403 })
  assert.deepEqual(wasm.checkStorageGet(0, null, CHUNK), { kind: 'failed', status: 0 })
  for (const bad of [-1, NaN, Infinity, 1.5]) {
    assert.equal(codeOf(() => wasm.checkStorageGet(200, bad, CHUNK)), 'length_invalid', `len ${bad}`)
    assert.equal(codeOf(() => wasm.checkStorageGet(200, null, bad)), 'length_invalid', `expected ${bad}`)
  }
  // The status crosses the same validation as the body's head, never a silent truncation:
  // 65736 is not a u16 and 200.9 is not a whole number.
  for (const bad of [65736, 200.9]) {
    assert.equal(codeOf(() => wasm.checkStorageGet(bad, CHUNK, CHUNK)), 'status_invalid', `status ${bad}`)
    assert.equal(codeOf(() => wasm.WasmStorageBody.fromHead(bad, CHUNK, CHUNK)), 'status_invalid', `head ${bad}`)
  }
  // 1000 is a whole number that fits a u16: the binding only converts it, and core's rule (the
  // same on every binding) makes it a failed head carrying 1000.
  assert.deepEqual(wasm.checkStorageGet(1000, CHUNK, CHUNK), { kind: 'failed', status: 1000 })
})

test('pacedUntilMs carries desktop formula and the no-ceiling sentinel', () => {
  assert.equal(wasm.pacedUntilMs(1000, 10000, 0), -Infinity, 'no ceiling is -Infinity')
  assert.equal(wasm.pacedUntilMs(1000, 0, 8), 1000)
  assert.equal(wasm.pacedUntilMs(1000, 8192, 8), 2000, '8 KiB at 8 KiB/s')
  assert.ok(Number.isFinite(wasm.pacedUntilMs(0, Number.MAX_SAFE_INTEGER, 1)), 'a big finite wait stays finite')
  for (const bad of [-1, NaN, Infinity, 1.5]) {
    assert.equal(codeOf(() => wasm.pacedUntilMs(1000, bad, 8)), 'bytes_invalid', `bytes ${bad}`)
    assert.equal(codeOf(() => wasm.pacedUntilMs(1000, 0, bad)), 'kbps_invalid', `kbps ${bad}`)
  }
})

test('checkStorageBody: only the counted bytes decide, after a 200 head', () => {
  assert.deepEqual(wasm.checkStorageBody(CHUNK, CHUNK), { kind: 'stored' })
  assert.deepEqual(wasm.checkStorageBody(CHUNK - 1, CHUNK), { kind: 'failed', status: 200 }, 'short')
  assert.deepEqual(wasm.checkStorageBody(CHUNK + 1, CHUNK), { kind: 'failed', status: 200 }, 'long')
  assert.deepEqual(wasm.checkStorageBody(0, 0), { kind: 'stored' })
  assert.equal(codeOf(() => wasm.checkStorageBody(NaN, CHUNK)), 'length_invalid')
})

test('maxInFlightBytes names the four classes', () => {
  const MiB = 1024 * 1024
  assert.equal(wasm.maxInFlightBytes('native'), 256 * MiB)
  assert.equal(wasm.maxInFlightBytes('browser'), 64 * MiB)
  assert.equal(wasm.maxInFlightBytes('mobile_app'), 64 * MiB)
  assert.equal(wasm.maxInFlightBytes('mobile_extension'), 16 * MiB)
  assert.equal(codeOf(() => wasm.maxInFlightBytes('desktop')), 'class_invalid')
})

test('pairsAllowed refuses a missing pair, a missing token and a bucket-case change', () => {
  const discovery = {
    download: ['object-download-v1'],
    upload: [],
    storage_buckets: [
      { host: 's3.storage.test', bucket: 'bb-01' },
      { host: 'eu.storage.test', bucket: 'vault' },
    ],
  }
  const all = [
    { host: 's3.storage.test', bucket: 'bb-01' },
    { host: 'eu.storage.test', bucket: 'vault' },
  ]
  assert.equal(wasm.pairsAllowed(discovery, 'download', all), true)
  assert.equal(wasm.pairsAllowed(discovery, 'download', all.slice(0, 1)), false, 'one pair missing')
  assert.equal(wasm.pairsAllowed(discovery, 'upload', all), false, 'upload not offered')
  assert.equal(
    wasm.pairsAllowed(discovery, 'download', [{ host: 'S3.STORAGE.TEST', bucket: 'bb-01' }, all[1]]),
    true,
    'hosts are case-insensitive',
  )
  assert.equal(
    wasm.pairsAllowed(discovery, 'download', [{ host: 's3.storage.test', bucket: 'BB-01' }, all[1]]),
    false,
    'buckets are exact',
  )
  assert.equal(
    wasm.pairsAllowed({ download: ['object-download-v1'], upload: [], storage_buckets: [] }, 'download', []),
    false,
    'no listed bucket is not vacuously allowed',
  )
})

test('pairsAllowed: discovery is named first, then direction, then pairs', () => {
  const discovery = { download: ['object-download-v1'], upload: [], storage_buckets: [] }
  assert.equal(
    codeOf(() => wasm.pairsAllowed('not-an-object', 'sideways', [])),
    'discovery_invalid',
    'a bad discovery is named before a bad direction',
  )
  assert.equal(
    codeOf(() => wasm.pairsAllowed(discovery, 'sideways', 'not-an-array')),
    'direction_invalid',
    'a bad direction is named before a bad pairs argument',
  )
  assert.equal(codeOf(() => wasm.pairsAllowed(discovery, 'download', 'not-an-array')), 'pairs_invalid')
})

test('the count inputs refuse a number JS cannot hold exactly', () => {
  assert.equal(codeOf(() => wasm.pacedUntilMs(0, 2 ** 53, 1)), 'bytes_invalid', '2^53 is not exact')
  assert.equal(codeOf(() => wasm.checkStorageGet(200, 2 ** 53, 1)), 'length_invalid', '2^53 is not exact')
})

test('WasmStorageBody counts the body and refuses the first byte past the grant', () => {
  const body = wasm.WasmStorageBody.fromHead(200, CHUNK, CHUNK)
  body.push(CHUNK)
  assert.deepEqual(body.finish(), { kind: 'stored' })

  const short = wasm.WasmStorageBody.fromHead(200, CHUNK, CHUNK)
  short.push(CHUNK - 1)
  assert.equal(codeOf(() => short.push(2)), 'failed', 'past the grant throws')
  assert.equal(statusOf(() => short.push(2)), 200, 'and the error carries the status')
  assert.deepEqual(short.finish(), { kind: 'failed', status: 200 }, 'the refused bytes were not counted')

  const empty = wasm.WasmStorageBody.fromHead(200, 0, 0)
  assert.deepEqual(empty.finish(), { kind: 'stored' })

  assert.equal(codeOf(() => wasm.WasmStorageBody.fromHead(206, CHUNK, CHUNK)), 'failed', 'a 206 head throws')
  assert.equal(statusOf(() => wasm.WasmStorageBody.fromHead(206, CHUNK, CHUNK)), 206, 'with the head status')
  assert.equal(statusOf(() => wasm.WasmStorageBody.fromHead(403, CHUNK, CHUNK)), 403)
  assert.equal(statusOf(() => wasm.WasmStorageBody.fromHead(0, null, CHUNK)), 0, 'no answer keeps status 0')
  assert.equal(codeOf(() => wasm.WasmStorageBody.fromHead(200, null, CHUNK)), 'failed', 'no length throws')
})

test('WasmStorageBody.fromHead takes a whole status that fits a u16', () => {
  assert.equal(codeOf(() => wasm.WasmStorageBody.fromHead(65736, CHUNK, CHUNK)), 'status_invalid')
  assert.equal(codeOf(() => wasm.WasmStorageBody.fromHead(200.9, CHUNK, CHUNK)), 'status_invalid')
  assert.equal(codeOf(() => wasm.WasmStorageBody.fromHead(-1, CHUNK, CHUNK)), 'status_invalid')
  assert.equal(codeOf(() => wasm.WasmStorageBody.fromHead(NaN, CHUNK, CHUNK)), 'status_invalid')
  assert.equal(statusOf(() => wasm.WasmStorageBody.fromHead(999, 0, 0)), 999, '999 is a whole status, not a bad one')
  assert.equal(statusOf(() => wasm.WasmStorageBody.fromHead(1000, CHUNK, CHUNK)), 1000, '1000 fits a u16: a failed head, not a caller error')
})

test('directTransferConstants carries the three response caps', () => {
  const c = wasm.directTransferConstants()
  assert.equal(c.max_discovery_body_bytes, 256 * 1024)
  assert.equal(c.max_grant_body_bytes, 1024 * 1024)
  assert.equal(c.max_chunk_body_bytes, 256 * 1024 * 1024 + 28)
})

test('the planner chunk length is null before a window and the grant length after one', () => {
  const discovery = {
    download: ['object-download-v1'],
    upload: [],
    storage_hosts: ['s3.storage.test'],
    storage_buckets: [{ host: 's3.storage.test', bucket: 'bb-01' }],
    max_window: 32,
    url_ttl_seconds: 300,
  }
  const planner = new wasm.WasmDownloadPlanner(discovery, 'https://api.beebeeb.test', 'file-1', 7)
  assert.equal(planner.chunkLength(0), null, 'no geometry before the first window')

  const first = planner.poll(1_800_000_000_000)
  assert.equal(first.kind, 'request_window')
  const answer = {
    transport: 'object-download-v1',
    file_id: 'file-1',
    object_version_id: 'v1',
    chunk_count: 2,
    chunk_size: 4 * 1024 * 1024,
    encrypted_size: 4 * 1024 * 1024 + 100 + 56,
    original_size: 4 * 1024 * 1024 + 100,
    grants: [
      { index: 0, method: 'GET', url: 'https://s3.storage.test/bb-01/t/v/0.bin?X-Amz-Signature=SIG', length: CHUNK, expires_at: '2027-01-15T08:05:00Z' },
      { index: 1, method: 'GET', url: 'https://s3.storage.test/bb-01/t/v/1.bin?X-Amz-Signature=SIG', length: 100 + 28, expires_at: '2027-01-15T08:05:00Z' },
    ],
    next_index: null,
  }
  const code = planner.windowAnswered(new TextEncoder().encode(JSON.stringify(answer)), 1_800_000_000_000)
  assert.equal(code, 'accepted')
  assert.equal(planner.chunkLength(0), CHUNK)
  assert.equal(planner.chunkLength(1), 100 + 28)
  assert.equal(planner.chunkLength(2), null, 'there is no chunk 2')
})
