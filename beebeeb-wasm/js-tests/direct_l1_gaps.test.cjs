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
})

test('pacedUntilMs carries desktop formula and the no-ceiling sentinel', () => {
  assert.equal(wasm.pacedUntilMs(1000n, 10000n, 0n), -9223372036854775808n, 'no ceiling')
  assert.equal(wasm.pacedUntilMs(1000n, 0n, 8n), 1000n)
  assert.equal(wasm.pacedUntilMs(1000n, 8192n, 8n), 2000n, '8 KiB at 8 KiB/s')
  assert.equal(wasm.pacedUntilMs(1000n, 18446744073709551615n, 1n), 9223372036854775807n, 'saturates')
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
