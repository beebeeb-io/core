'use strict'
// The download-side direct-transfer exports as JS sees them (clients plan A1, A2 and the download half of A3): the
// time bounds cross as numbers, a bad argument as an `Error` with a stable `code`, and the planner's byte cap and
// storage breaker work through the real wasm-bindgen glue. The rows are the shared vectors
// (`test-vectors/direct_transfer.json`), the same ones core and the Rust seams run, so JS cannot drift from them.
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const pkg = process.env.BB_WASM_PKG
if (!pkg) throw new Error('BB_WASM_PKG must point at the wasm-pack --target nodejs output (js-tests/run.sh sets it)')
const wasm = require(path.resolve(pkg, 'beebeeb_wasm.js'))

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'test-vectors', 'direct_transfer.json'), 'utf8'))

function codeOf(fn) {
  try {
    fn()
  } catch (e) {
    return e.code
  }
  return 'did not throw'
}

// ── time bounds ──

test('the storage totals cross as milliseconds and refuse what is not a byte length', () => {
  assert.equal(wasm.storagePutTotalMs(4 * 1024 * 1024 + 28), 93000, 'a 4 MiB chunk: 60 s + 33 s')
  assert.equal(wasm.storageGetTotalMs(4 * 1024 * 1024 + 28), 93000)
  assert.equal(wasm.storagePutTotalMs(0), 60000)
  assert.equal(wasm.storagePutTotalMs(256 * 1024 * 1024 + 28), 2109000, 'the largest chunk')
  for (const bad of [-1, NaN, Infinity, 1.5, 2 ** 53]) {
    assert.equal(codeOf(() => wasm.storagePutTotalMs(bad)), 'length_invalid', `put ${bad}`)
    assert.equal(codeOf(() => wasm.storageGetTotalMs(bad)), 'length_invalid', `get ${bad}`)
  }
})

test('directTransferConstants carries the five time bounds', () => {
  const c = wasm.directTransferConstants()
  assert.equal(c.storage_connect_timeout_ms, 15000)
  assert.equal(c.storage_get_idle_ms, 30000)
  assert.equal(c.discovery_timeout_ms, 15000)
  assert.equal(c.api_call_timeout_ms, 60000)
  assert.equal(c.background_put_resource_timeout_ms, 240000)
})

// ── DirectHealth ──

function runHealthStep(h, step) {
  const now = step.now ?? 0
  switch (step.op) {
    case 'gave_up':
      return h.gaveUp(step.direction, now)
    case 'restore':
      return h.restore(step.direction, step.ms)
    case 'may_start':
      return assert.equal(h.mayStart(step.direction, now), step.expect, JSON.stringify(step))
    case 'may_start_file':
      return assert.equal(h.mayStartFile(step.direction, now, step.file_gave_up), step.expect, JSON.stringify(step))
    case 'last_gave_up': {
      // The generator drops a null `expect`: absent means "nothing recorded", which crosses as undefined here.
      const got = h.lastGaveUpMs(step.direction)
      return assert.equal(got ?? null, step.expect ?? null, JSON.stringify(step))
    }
    default:
      throw new Error(`unknown health op ${step.op}`)
  }
}

test('every health scenario of the vectors passes through the JS glue', () => {
  assert.ok(vectors.health.length >= 8)
  let steps = 0
  for (const scenario of vectors.health) {
    const h = new wasm.WasmDirectHealth()
    for (const step of scenario.steps) {
      runHealthStep(h, step)
      steps++
    }
  }
  assert.equal(steps, vectors.health.reduce((n, s) => n + s.steps.length, 0))
})

test('health refuses a direction that is not one, and records nothing for it', () => {
  const h = new wasm.WasmDirectHealth()
  for (const bad of ['', 'Download', 'up', 'both']) {
    assert.equal(codeOf(() => h.gaveUp(bad, 0)), 'direction_invalid', bad)
    assert.equal(codeOf(() => h.mayStart(bad, 0)), 'direction_invalid')
    assert.equal(codeOf(() => h.mayStartFile(bad, 0, false)), 'direction_invalid')
    assert.equal(codeOf(() => h.lastGaveUpMs(bad)), 'direction_invalid')
    assert.equal(codeOf(() => h.restore(bad, 0)), 'direction_invalid')
  }
  assert.equal(h.lastGaveUpMs('download') ?? null, null)
  assert.equal(h.lastGaveUpMs('upload') ?? null, null)
})

// ── resumeTransport ──

test('every resume_transport row of the vectors passes through the JS glue', () => {
  assert.ok(vectors.resume_transport.length >= 20)
  for (const row of vectors.resume_transport) {
    assert.equal(wasm.resumeTransport(row.recorded, row.discovery, row.forced_api), row.expect, row.name)
  }
})

test('resumeTransport refuses names it does not know', () => {
  assert.equal(codeOf(() => wasm.resumeTransport('sideways', { kind: 'unknown' }, false)), 'recorded_invalid')
  assert.equal(codeOf(() => wasm.resumeTransport('direct', { kind: 'offers' }, false)), 'discovery_state_invalid')
  assert.equal(codeOf(() => wasm.resumeTransport('direct', { kind: 'maybe' }, false)), 'discovery_state_invalid')
  assert.equal(codeOf(() => wasm.resumeTransport('direct', 'unknown', false)), 'discovery_state_invalid')
})

// ── the planner's byte cap and storage breaker, through the real glue ──

function planner(scenario) {
  const discovery = wasm.parseDirectDiscovery(Buffer.from(JSON.stringify(vectors.discoveries[scenario.discovery])))
  const p = new wasm.WasmDownloadPlanner(discovery, 'https://api.beebeeb.test', vectors.file_id, scenario.seed)
  if (scenario.max_in_flight_bytes !== undefined) p.setMaxInFlightBytes(scenario.max_in_flight_bytes)
  return p
}

/** What a poll looks like in the file: a fetch's link is a WasmSignedUrl in JS, its raw string in the vectors, and the
 * file's flat fetch has no `method` or `expires_at` (the Rust seam strips them the same way). */
function pollAsInTheFile(step) {
  if (step.kind !== 'fetch') return step
  const { method, expires_at, ...flat } = step
  return { ...flat, url: step.url.raw() }
}

/** The file's `expect` for a call that may fail: "ok", or the stable code of the Error it throws. */
function expectResult(step, call) {
  const got = codeOf(call)
  assert.equal(got === 'did not throw' ? 'ok' : got, step.expect ?? 'ok', JSON.stringify(step).slice(0, 200))
}

const OPS = new Set(['poll', 'window_answered', 'fetch_ok', 'fetch_failed', 'consumed', 'storage_given_up'])

function runPlannerStep(p, step) {
  const now = step.now ?? 0
  switch (step.op) {
    case 'poll': {
      const got = pollAsInTheFile(p.poll(now))
      if (step.expect.until_ms_between) {
        const [lo, hi] = step.expect.until_ms_between
        assert.equal(got.kind, 'wait', JSON.stringify(step))
        assert.ok(got.until_ms >= lo && got.until_ms <= hi, `wait until ${got.until_ms} not in ${lo}..${hi}`)
        return
      }
      return assert.deepEqual(got, step.expect, JSON.stringify(step))
    }
    case 'window_answered': {
      const body = step.body !== undefined ? Buffer.from(step.body) : Buffer.from(JSON.stringify(step.response))
      const code = p.windowAnswered(body, now)
      return assert.equal(code === 'accepted' ? 'ok' : code, step.expect ?? 'ok', JSON.stringify(step).slice(0, 200))
    }
    case 'fetch_ok':
      return expectResult(step, () => p.fetchOk(step.index))
    case 'fetch_failed':
      return expectResult(step, () => p.fetchFailed(step.index, now))
    case 'consumed':
      return expectResult(step, () => p.consumed(step.index))
    case 'storage_given_up':
      return assert.equal(p.storageGivenUp(), step.expect, JSON.stringify(step))
    default:
      throw new Error(`op ${step.op} is not run here`)
  }
}

const plannable = vectors.planner.filter((s) => s.steps && s.steps.every((st) => OPS.has(st.op)))

test('the scenarios of the vectors that use only calls JS makes run through the glue, including the cap and the breaker', () => {
  const names = plannable.map((s) => s.name)
  for (const needed of [
    'storage that never answers trips the breaker after the first exhausted chunk',
    'after one chunk from storage, the failures of another chunk do not trip the breaker',
    'a 64 MiB cap holds three chunks of 16 MiB: the 28 bytes of overhead count',
    'with a cap of one, a failing chunk blocks the next fetch',
    'a client clock ten minutes ahead still completes a file with one window request',
  ]) {
    assert.ok(names.includes(needed), `"${needed}" runs here`)
  }
  for (const scenario of plannable) {
    const p = planner(scenario)
    for (const [i, step] of scenario.steps.entries()) {
      try {
        runPlannerStep(p, step)
      } catch (e) {
        e.message = `${scenario.name}, step ${i}: ${e.message}`
        throw e
      }
    }
  }
})

test('setMaxInFlightBytes refuses a number that is not a byte count', () => {
  const p = planner({ discovery: 'std', seed: 1 })
  for (const bad of [-1, NaN, Infinity, 1.5, 2 ** 53]) {
    assert.equal(codeOf(() => p.setMaxInFlightBytes(bad)), 'bytes_invalid', `${bad}`)
  }
  p.setMaxInFlightBytes(0)
  assert.equal(p.storageGivenUp(), false, 'a new planner has not given up storage')
})
