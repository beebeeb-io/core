'use strict';
// Task 2275 L13: no WASM export may seal a NEW item from plain id text or a raw
// key, and no replacement may be sealed from a bare id either. The handles core
// mints (`WasmNewItemId`, `WasmWriteTarget`) are the only inputs the sealers
// take. This test reads the generated `.d.ts` so it fails if such an export
// reappears, without anyone having to remember to update a list of calls.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const pkg = process.env.BB_WASM_PKG;
if (!pkg) throw new Error('BB_WASM_PKG is not set');
const dts = fs.readFileSync(path.join(pkg, 'beebeeb_wasm.d.ts'), 'utf8');

// `export function name(params): ret;` — params may span one line.
const functions = new Map();
for (const m of dts.matchAll(/export function (\w+)\(([^)]*)\)\s*:\s*([^;]+);/g)) {
  functions.set(m[1], { params: m[2].trim(), ret: m[3].trim() });
}

// The parameter names/types of one signature, split on top-level commas.
const paramList = (sig) => {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of sig) {
    if (ch === '<' || ch === '(' || ch === '[' || ch === '{') depth += 1;
    if (ch === '>' || ch === ')' || ch === ']' || ch === '}') depth -= 1;
    if (ch === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
};

const typeOf = (param) => {
  const idx = param.indexOf(':');
  return idx === -1 ? param.trim() : param.slice(idx + 1).trim();
};

// name -> the handle its first parameter must be
const HANDLE_SEALERS = new Map([
  ['encryptNameForNewItem', 'WasmNewItemId'],
  ['encryptNoteForNewItem', 'WasmNewItemId'],
  ['encryptThumbnailForNewItem', 'WasmNewItemId'],
  ['encryptNameForTarget', 'WasmWriteTarget'],
  ['encryptNoteForTarget', 'WasmWriteTarget'],
  ['encryptThumbnailForTarget', 'WasmWriteTarget'],
]);

test('every new-item and target sealer takes an opaque handle first', () => {
  for (const [name, handle] of HANDLE_SEALERS) {
    const fn = functions.get(name);
    assert.ok(fn, `${name} must be exported`);
    const params = paramList(fn.params);
    assert.ok(params.length > 0, `${name} must take the handle`);
    assert.equal(
      typeOf(params[0]),
      handle,
      `${name} must take a ${handle}, not ${typeOf(params[0])}`,
    );
  }
});

test('no sealer takes a master key, a file id or a raw key in the handle slot', () => {
  for (const [name, fn] of functions) {
    if (!/For(NewItem|Target)$/.test(name)) continue;
    const first = typeOf(paramList(fn.params)[0] ?? '');
    assert.ok(
      first === 'WasmNewItemId' || first === 'WasmWriteTarget',
      `${name} takes ${first} first; a bare id, master key or raw key must not seal`,
    );
    for (const param of paramList(fn.params)) {
      const [paramName, type] = [param.split(':')[0].trim(), typeOf(param)];
      assert.ok(
        !/^(file_key|file_id|master_key|key|id|item_id)$/.test(paramName) || type.startsWith('Wasm'),
        `${name} must not take ${paramName}: ${type}`,
      );
    }
  }
});

test('the target sealers take no pin: the handle carries it', () => {
  for (const name of ['encryptNameForTarget', 'encryptNoteForTarget', 'encryptThumbnailForTarget']) {
    const types = paramList(functions.get(name).params).map(typeOf);
    assert.ok(!types.includes('number'), `${name} must not take a pin or id number`);
  }
});

test('minting returns handles, and the handles cannot be built from text', () => {
  for (const name of ['newOwnerItemId', 'newForeignItemId']) {
    const fn = functions.get(name);
    assert.ok(fn, `${name} must be exported`);
    assert.equal(fn.ret, 'WasmNewItemId', `${name} must return a handle`);
  }
  const resume = functions.get('resumeNewItemId');
  assert.ok(resume, 'resumeNewItemId must be exported');
  assert.equal(resume.ret, 'WasmNewItemId');

  for (const handle of ['WasmNewItemId', 'WasmWriteTarget']) {
    assert.ok(dts.includes(`export class ${handle}`), `${handle} must be exported as a class`);
    const body = dts.slice(dts.indexOf(`export class ${handle}`));
    const end = body.indexOf('\n}');
    const block = end === -1 ? body : body.slice(0, end);
    assert.ok(
      !/^\s*constructor\s*\(/m.test(block),
      `${handle} must have no public constructor: only core mints it`,
    );
  }
});

test('the chunk encryptor has a handle-based constructor for each write path', () => {
  const body = dts.slice(dts.indexOf('export class WasmChunkEncryptor'));
  const block = body.slice(0, body.indexOf('\n}'));
  for (const [method, handle] of [
    ['forNewItem', 'WasmNewItemId'],
    ['forTarget', 'WasmWriteTarget'],
  ]) {
    const m = block.match(new RegExp(`static ${method}\\(([^)]*)\\)\\s*:\\s*WasmChunkEncryptor`));
    assert.ok(m, `WasmChunkEncryptor.${method} must be a static constructor`);
    assert.equal(typeOf(paramList(m[1].trim())[0]), handle, `${method} must take a ${handle}`);
  }
});
