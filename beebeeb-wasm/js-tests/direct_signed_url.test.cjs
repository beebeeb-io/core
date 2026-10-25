'use strict'
// The presigned link of a `fetch` step is a bearer capability. The step the planner hands to JS carries it as a
// `WasmSignedUrl` object, so that nothing a web client does by habit (console.log, String(), a template literal,
// JSON.stringify, util.inspect) shows it. These tests run the real wasm module under node and look at what JS sees;
// `cargo test` cannot, because the swap lives in the JsValue path (`direct_poll_to_js`).
const test = require('node:test')
const assert = require('node:assert/strict')
const util = require('node:util')
const fs = require('node:fs')
const path = require('node:path')

const pkg = process.env.BB_WASM_PKG
if (!pkg) throw new Error('BB_WASM_PKG must point at the wasm-pack --target nodejs output (js-tests/run.sh sets it)')
let wasm
let loadError
try {
  wasm = require(path.resolve(pkg, 'beebeeb_wasm.js'))
} catch (e) {
  loadError = e
}

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'test-vectors', 'direct_transfer.json'), 'utf8'))
// "a window body sent as text": poll -> request_window, the window answer (a JSON text), poll -> fetch(0).
const scenario = vectors.planner.find((s) => s.name === 'a window body sent as text')
const T0 = scenario.steps[0].now
const WINDOW = scenario.steps[1].body
const RAW_LINK = JSON.parse(WINDOW).grants[0].url // https://s3.storage.test/bb-01/t/v/0.bin?X-Amz-Signature=SIG0
const SECRETS = ['X-Amz', 'SIG0', 'Signature', '/bb-01/t/v/0.bin']

// Doc comments are copied into the generated glue as JSDoc blocks: a block-comment closer inside one ends it early.
function docCommentsThatCloseEarly(file) {
  const bad = []
  let inBlock = false
  fs.readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
    if (!inBlock) {
      if (line.includes('/**') && !/\*\/\s*$/.test(line)) inBlock = true
    } else if (line.includes('*/')) {
      if (!/^\s*\*\/\s*$/.test(line)) bad.push(`${path.basename(file)}:${i + 1}: ${line.trim().slice(0, 100)}`)
      inBlock = false
    }
  })
  return bad
}

test('the generated glue loads, and no doc comment in it or in the declarations closes early', () => {
  assert.ifError(loadError)
  assert.deepEqual(docCommentsThatCloseEarly(path.resolve(pkg, 'beebeeb_wasm.js')), [])
  assert.deepEqual(docCommentsThatCloseEarly(path.resolve(pkg, 'beebeeb_wasm.d.ts')), [])
})

function planner(seed) {
  const discovery = wasm.parseDirectDiscovery(Buffer.from(JSON.stringify(vectors.discoveries[scenario.discovery])))
  return new wasm.WasmDownloadPlanner(discovery, 'https://api.beebeeb.test', vectors.file_id, seed)
}

/** A planner that was given its first window and now says "fetch chunk 0". */
function atFetch(seed = scenario.seed) {
  const p = planner(seed)
  assert.equal(p.poll(T0).kind, 'request_window')
  assert.equal(p.windowAnswered(Buffer.from(WINDOW), T0), 'accepted')
  const step = p.poll(T0)
  assert.equal(step.kind, 'fetch')
  return { p, step }
}

function assertNoSecret(shown, what) {
  for (const secret of SECRETS) {
    assert.ok(!shown.includes(secret), `${what} shows ${JSON.stringify(secret)}: ${shown}`)
  }
}

test('the link of a fetch step is an object, not a string', () => {
  const { step } = atFetch()
  assert.equal(typeof step.url, 'object')
  assert.ok(step.url instanceof wasm.WasmSignedUrl)
  assert.equal(step.index, 0)
  assert.equal(step.method, 'GET')
})

test('raw() is the one way to the link, by name', () => {
  const { step } = atFetch()
  assert.equal(step.url.raw(), RAW_LINK)
})

test('JSON.stringify(step) and util.inspect(step) do not show the signature', () => {
  const { step } = atFetch()
  const json = JSON.stringify(step)
  assertNoSecret(json, 'JSON.stringify(step)')
  assert.ok(json.includes('s3.storage.test'), `the host is still there for a log line: ${json}`)
  for (const options of [{}, { depth: null }, { depth: null, showHidden: true }, { depth: null, showProxy: true }]) {
    assertNoSecret(util.inspect(step, options), `util.inspect(step, ${JSON.stringify(options)})`)
  }
})

test('String(url), a template literal, redacted() and toJSON() are the redacted form', () => {
  const { step } = atFetch()
  const redacted = wasm.redactUrl(RAW_LINK)
  assertNoSecret(redacted, 'redactUrl')
  assert.notEqual(redacted, RAW_LINK)
  assert.equal(String(step.url), redacted)
  assert.equal(`${step.url}`, redacted)
  assert.equal(step.url + '', redacted)
  assert.equal(step.url.redacted(), redacted)
  assert.equal(step.url.toJSON(), redacted)
})

test('the formats a logger uses do not show the signature either', () => {
  const { step } = atFetch()
  assertNoSecret(util.format('%s | %o | %O | %j | %d', step.url, step, step, step, 1), 'util.format')
  assertNoSecret(util.format(step), 'util.format(step)')
})

test('a WasmSignedUrl does not survive structuredClone as a usable link', () => {
  // The object holds a pointer into wasm memory. A structured clone (postMessage to a worker) keeps no
  // methods and no link: hand a worker `step.url.raw()` (a string) at the moment it fetches, nothing else.
  const { step } = atFetch()
  let clone
  try {
    clone = structuredClone(step)
  } catch (e) {
    assert.equal(e.name, 'DataCloneError')
    return
  }
  assert.notEqual(typeof clone.url.raw, 'function')
  assertNoSecret(JSON.stringify(clone), 'JSON.stringify(structuredClone(step))')
  assertNoSecret(util.inspect(clone, { depth: null }), 'util.inspect(structuredClone(step))')
})

test('a step that carries no link stays a plain object', () => {
  const p = planner(scenario.seed)
  const step = p.poll(T0)
  assert.equal(step.kind, 'request_window')
  assert.equal(step.url, undefined)
  assert.equal(JSON.parse(JSON.stringify(step)).kind, 'request_window')
})

test('Math.random() is a usable jitter seed through the JS boundary', () => {
  // A seed below 1 used to collapse to 0 (`as u64`): one retry schedule for every tab.
  const waitAfterAFailure = (seed) => {
    const { p } = atFetch(seed) // chunk 0 in flight
    p.poll(T0) // chunk 1
    p.poll(T0) // chunk 2: the window's three chunks are all in flight
    p.fetchFailed(0, T0)
    const next = p.poll(T0)
    assert.equal(next.kind, 'wait', JSON.stringify(next))
    return next.until_ms
  }
  const seeds = [0.05, 0.1, 0.3, 0.5, 0.7, 0.9]
  const waits = seeds.map(waitAfterAFailure)
  assert.ok(new Set(waits).size > 1, `${seeds.length} different seeds gave one schedule: ${waits}`)
  assert.equal(waitAfterAFailure(0.3), waitAfterAFailure(0.3), 'the same seed repeats its schedule')
})
