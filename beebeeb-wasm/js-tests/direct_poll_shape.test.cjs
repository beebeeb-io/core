'use strict'
// The `.d.ts` types of `poll()` (`DirectPoll`, `DirectVerdict`) are written by hand in `beebeeb-wasm/src/lib.rs`
// (a typescript_custom_section), while the values are serialised by serde from `DirectPollJs`. Nothing in the compiler
// ties the two. This test drives a real planner into every kind of `poll()` and checks the keys of what JS actually
// gets against the keys the generated declarations promise, so a field added or renamed on one side turns it red.
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const pkg = process.env.BB_WASM_PKG
if (!pkg) throw new Error('BB_WASM_PKG must point at the wasm-pack --target nodejs output (js-tests/run.sh sets it)')
const wasm = require(path.resolve(pkg, 'beebeeb_wasm.js'))
const dts = fs.readFileSync(path.resolve(pkg, 'beebeeb_wasm.d.ts'), 'utf8')

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'test-vectors', 'direct_transfer.json'), 'utf8'))
const scenario = vectors.planner.find((s) => s.name === 'a window body sent as text')
const T0 = scenario.steps[0].now
const WINDOW = scenario.steps[1].body

// ── the declared shape, read from the generated .d.ts ──

function splitTop(text, sep) {
  const parts = []
  let depth = 0
  let cur = ''
  for (const ch of text) {
    if (ch === '{') depth++
    if (ch === '}') depth--
    if (ch === sep && depth === 0) {
      parts.push(cur)
      cur = ''
    } else {
      cur += ch
    }
  }
  parts.push(cur)
  return parts.map((p) => p.trim()).filter(Boolean)
}

/** `{ a: x; b: { c: y } }` -> { a: 'x', b: '{ c: y }' } (top-level keys with their type text). */
function fieldsOf(objectText) {
  const body = objectText.trim().replace(/^\{/, '').replace(/\}$/, '')
  const fields = {}
  for (const field of splitTop(body, ';')) {
    const at = field.indexOf(':')
    fields[field.slice(0, at).trim()] = field.slice(at + 1).trim()
  }
  return fields
}

/** The members of `export type NAME = | {...} | {...};` (one member per line), by their `kind`. */
function declaredMembers(name) {
  const start = dts.indexOf(`export type ${name} =`)
  assert.ok(start >= 0, `${name} is declared`)
  const members = {}
  for (const line of dts.slice(start).split('\n').slice(1)) {
    const text = line.trim().replace(/^\|\s*/, '').replace(/;$/, '')
    if (!text.startsWith('{')) break
    const fields = fieldsOf(text)
    const kind = /^"(.*)"$/.exec(fields.kind)[1]
    members[kind] = fields
    if (line.trim().endsWith(';')) break
  }
  return members
}

const poll = declaredMembers('DirectPoll')
const verdict = declaredMembers('DirectVerdict')

function keysOf(value) {
  return Object.keys(value).sort()
}

function assertShape(live, what) {
  const declared = poll[live.kind]
  assert.ok(declared, `${what}: DirectPoll declares kind ${live.kind}`)
  assert.deepEqual(keysOf(live), Object.keys(declared).sort(), `${what}: keys of a ${live.kind} step`)
  if (live.kind === 'request_window') {
    assert.deepEqual(keysOf(live.request), Object.keys(fieldsOf(declared.request)).sort(), `${what}: keys of the request`)
  }
  if (live.kind === 'stop') {
    const v = verdict[live.verdict.kind]
    assert.ok(v, `${what}: DirectVerdict declares kind ${live.verdict.kind}`)
    assert.deepEqual(keysOf(live.verdict), Object.keys(v).sort(), `${what}: keys of a ${live.verdict.kind} verdict`)
  }
}

// ── a real planner, driven into every kind ──

function planner() {
  const discovery = wasm.parseDirectDiscovery(Buffer.from(JSON.stringify(vectors.discoveries[scenario.discovery])))
  return new wasm.WasmDownloadPlanner(discovery, 'https://api.beebeeb.test', vectors.file_id, scenario.seed)
}

function afterTheWindow() {
  const p = planner()
  assert.equal(p.poll(T0).kind, 'request_window')
  assert.equal(p.windowAnswered(Buffer.from(WINDOW), T0), 'accepted')
  return p
}

const reached = {
  request_window: () => planner().poll(T0),
  fetch: () => afterTheWindow().poll(T0),
  fetch_via_api: () => {
    const p = afterTheWindow()
    assert.equal(p.poll(T0).kind, 'fetch')
    p.fetchOk(0)
    p.chunkUnauthentic(0)
    return p.poll(T0)
  },
  wait: () => {
    const p = afterTheWindow()
    for (let i = 0; i < 3; i++) assert.equal(p.poll(T0).kind, 'fetch')
    p.fetchFailed(0, T0)
    return p.poll(T0)
  },
  done: () => {
    const p = afterTheWindow()
    for (let i = 0; i < 3; i++) assert.equal(p.poll(T0).kind, 'fetch')
    for (let i = 0; i < 3; i++) p.fetchOk(i)
    for (let i = 0; i < 3; i++) p.consumed(i)
    return p.poll(T0)
  },
  'stop (terminal)': () => {
    const p = planner()
    p.poll(T0)
    p.windowFailed({ kind: 'terminal', status: 403, error: 'forbidden' }, T0)
    return p.poll(T0)
  },
  'stop (restart)': () => {
    const p = planner()
    p.poll(T0)
    p.windowFailed({ kind: 'restart' }, T0)
    return p.poll(T0)
  },
  'stop (api_for_file)': () => {
    const p = planner()
    p.poll(T0)
    p.windowMalformed()
    return p.poll(T0)
  },
  'stop (corrupt)': () => {
    const p = afterTheWindow()
    p.poll(T0)
    p.fetchOk(0)
    p.chunkUnauthentic(0)
    assert.equal(p.poll(T0).kind, 'fetch_via_api')
    p.fetchOk(0)
    p.chunkUnauthentic(0)
    return p.poll(T0)
  },
}

for (const [what, reach] of Object.entries(reached)) {
  test(`a ${what} step has the keys the .d.ts declares`, () => {
    assertShape(reach(), what)
  })
}

test('every kind the .d.ts declares is driven here, and every verdict', () => {
  const driven = new Set()
  const verdicts = new Set()
  for (const reach of Object.values(reached)) {
    const live = reach()
    driven.add(live.kind)
    if (live.kind === 'stop') verdicts.add(live.verdict.kind)
  }
  assert.deepEqual([...driven].sort(), Object.keys(poll).sort())
  assert.deepEqual([...verdicts].sort(), Object.keys(verdict).sort())
})
