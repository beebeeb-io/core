'use strict';
// The device-link surface a web client sees (crypto review, P2-3 and
// P2-1): the QR path takes the raw scanned text, never fingerprint bytes, and
// carries the device name the approver shows (Guus's ruling of 2026-11-07);
// the typed-code path runs both roles with the approver's confirmation check
// before anything is sealed.
const assert = require('node:assert/strict');
const nodeTest = require('node:test');
const wasm = require(process.env.BB_WASM_PKG);

const MASTER = new Uint8Array(32).fill(7);
const SESSION = new Uint8Array(16).fill(3);
const hex = (bytes) => Buffer.from(bytes).toString('hex');

function otherCode(code) {
  return (code[0] === '2' ? '3' : '2') + code.slice(1);
}

nodeTest('QR path: core parses the scanned text and seals to the scanned key only', () => {
  const link = new wasm.WasmNewDeviceLink(SESSION, '  Web laptop ');
  const fields = link.publicFields();
  assert.equal(fields.device_name, 'Web laptop');
  assert.ok(fields.qr_payload.startsWith('beebeeb-link:v2:'));
  assert.equal(fields.fingerprint, undefined, 'no fingerprint bytes leave core');
  assert.equal(wasm.scannedDeviceLinkName(fields.qr_payload), 'Web laptop', 'the name to show comes from the scan');
  assert.throws(() => wasm.scannedDeviceLinkName(fields.qr_payload.replace('v2:', 'v1:')));

  // A QR text built from anything but a scan is not accepted as bytes.
  assert.throws(() =>
    wasm.sealDeviceLink(MASTER, hex(fields.session_id), fields.public_key, 'Web laptop', link.typedCode()),
  );
  // The right text but a substituted key: refused before sealing.
  assert.throws(() =>
    wasm.sealDeviceLink(MASTER, fields.qr_payload, new Uint8Array(32).fill(9), 'Web laptop', link.typedCode()),
  );
  // The right text and key, but the relay rewrote the name: refused before sealing.
  assert.throws(
    () => wasm.sealDeviceLink(MASTER, fields.qr_payload, fields.public_key, 'Attacker phone', link.typedCode()),
    (error) => error.message === 'device_name_changed',
  );

  const sealed = wasm.sealDeviceLink(MASTER, fields.qr_payload, fields.public_key, 'Web laptop', link.typedCode());
  const material = link.open(sealed.approver_public, sealed.nonce, sealed.ciphertext);
  assert.ok(material);
  assert.throws(() => link.typedCode(), /consumed/);
});

nodeTest('typed-code path: approver first, confirmation before sealing, one attempt each', () => {
  const link = new wasm.WasmNewDeviceLink(SESSION, 'Web laptop');
  const code = link.typedCode();
  const approval = new wasm.WasmTypedApproval(code, SESSION, 'Web laptop');
  assert.equal(approval.deviceName, 'Web laptop');
  assert.throws(() => approval.seal(MASTER), /not confirmed/, 'nothing is sealed before confirm');

  const fresh = new wasm.WasmTypedApproval(code, SESSION, 'Web laptop');
  const receiver = link.answerTypedCode(fresh.message);
  assert.equal(receiver.message.length, 82);
  fresh.confirm(receiver.message);
  const sealed = fresh.seal(MASTER);
  assert.equal(sealed.ciphertext.length, 80);
  assert.ok(receiver.open(sealed.nonce, sealed.ciphertext));
  assert.throws(() => receiver.open(sealed.nonce, sealed.ciphertext), /already been used/);
});

nodeTest('typed-code path: a wrong code or a rewritten name fails at the approver', () => {
  for (const [approverCode, relayedName] of [
    [null, 'Attacker phone'],
    ['wrong', 'Web laptop'],
  ]) {
    const link = new wasm.WasmNewDeviceLink(SESSION, 'Web laptop');
    const code = approverCode === 'wrong' ? otherCode(link.typedCode()) : link.typedCode();
    const approval = new wasm.WasmTypedApproval(code, SESSION, relayedName);
    const receiver = link.answerTypedCode(approval.message);
    assert.throws(() => approval.confirm(receiver.message), (error) => error.message === 'confirmation_failed');
    assert.throws(() => approval.seal(MASTER), /not confirmed/);
  }
});

nodeTest('typed-code path: a non-canonical relayed name and malformed answers are refused', () => {
  assert.throws(() => new wasm.WasmTypedApproval('K7QM-4WTD', SESSION, ' Web laptop'), /malformed_answer/);
  const approval = new wasm.WasmTypedApproval('K7QM-4WTD', SESSION, 'Web laptop');
  assert.throws(() => approval.confirm(new Uint8Array(82)), (error) => error.message === 'malformed_answer');
  const link = new wasm.WasmNewDeviceLink(SESSION, 'Web laptop');
  assert.throws(() => link.answerTypedCode(new Uint8Array(34)), (error) => error.message === 'malformed_answer');
});
