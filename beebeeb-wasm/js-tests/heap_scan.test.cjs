'use strict';
// Task 2254 (decision L17): after an export returns, no raw secret bytes may
// remain in the WASM heap.
//
// For every export that takes or returns a secret (the audited list below), call
// it with fixture secrets and then scan the WHOLE WASM heap
// `[__heap_base, memory.buffer.byteLength)` for the 16-byte tail of every
// secret used in that call. A secret shorter than 16 bytes is searched whole
// (there is no 16-byte tail to search).
//
// The heap lower bound is `__heap_base` on purpose: Rust's shadow stack and the
// static data live below it, and the L17 claim is about the allocator-owned heap
// only (shadow-stack copies during a call are a named residual).
//
// Objects that legitimately HOLD key material while alive (chunk encryptor /
// decryptor, search index) are `.free()`d before the scan: the claim is about
// state after the export returns, not about live handles.
//
// Run via beebeeb-wasm/js-tests/memory.sh (builds the release nodejs package).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PKG = process.env.BB_WASM_PKG;
if (!PKG) {
  console.error('BB_WASM_PKG must point at the nodejs package dir; run js-tests/memory.sh');
  process.exit(2);
}
// Resolve the package: wasm-pack writes a package.json (so the directory is
// require-able), the bare wasm-bindgen CLI only writes the glue file.
function loadPackage() {
  try {
    return require(PKG);
  } catch (dirErr) {
    try {
      return require(path.join(PKG, 'beebeeb_wasm.js'));
    } catch {
      throw dirErr;
    }
  }
}

// The nodejs glue keeps its `WebAssembly.Instance` private, so capture the
// instance while it is being constructed: its exports carry `memory` and, when
// the linker exports it, the `__heap_base` global the scan is bounded by.
function instantiate() {
  const RealInstance = WebAssembly.Instance;
  let captured = null;
  WebAssembly.Instance = function patched(module, imports) {
    const inst = Reflect.construct(RealInstance, [module, imports]);
    captured = inst;
    return inst;
  };
  let mod;
  try {
    mod = loadPackage();
  } finally {
    WebAssembly.Instance = RealInstance;
  }
  assert.ok(captured, 'could not capture the WebAssembly.Instance the glue built');
  return { mod, ex: captured.exports };
}

const { mod: wasm, ex: wasmExports } = instantiate();

// The release module does not export `__heap_base` (checked: the export section
// has only `memory` and functions), so read the initial stack pointer out of the
// wasm global section: rustc/wasm-ld place the stack directly below the heap and
// initialise `__stack_pointer` to `__heap_base`. The stack therefore stays out of
// the scan — the L17 claim covers the allocator heap, and shadow-stack copies are
// a named residual.
function wasmFile() {
  if (process.env.BB_WASM_FILE) return process.env.BB_WASM_FILE;
  return path.join(PKG, 'beebeeb_wasm_bg.wasm');
}

function readHeapBase(file) {
  const buf = fs.readFileSync(file);
  let o = 8; // magic + version
  const u32leb = () => {
    let r = 0;
    let shift = 0;
    let b;
    do {
      b = buf[o++];
      r |= (b & 0x7f) << shift;
      shift += 7;
    } while (b & 0x80);
    return r >>> 0;
  };
  const i32leb = () => {
    let r = 0;
    let shift = 0;
    let b;
    do {
      b = buf[o++];
      r |= (b & 0x7f) << shift;
      shift += 7;
    } while (b & 0x80);
    if (shift < 32 && b & 0x40) r |= -1 << shift;
    return r;
  };
  while (o < buf.length) {
    const id = buf[o++];
    const size = u32leb();
    const end = o + size;
    if (id === 6) {
      const count = u32leb();
      const globals = [];
      for (let i = 0; i < count; i += 1) {
        const valtype = buf[o++];
        const mut = buf[o++];
        const op = buf[o++];
        let value = null;
        if (op === 0x41) value = i32leb();
        else if (op === 0x42) throw new Error('unexpected i64 global initialiser');
        else throw new Error(`unexpected global initialiser opcode 0x${op.toString(16)}`);
        o += 1; // end opcode
        globals.push({ valtype, mut, value });
      }
      const mutableI32 = globals.filter((g) => g.valtype === 0x7f && g.mut === 1);
      assert.equal(mutableI32.length, 1, `expected one mutable i32 global (__stack_pointer), got ${JSON.stringify(globals)}`);
      return mutableI32[0].value;
    }
    o = end;
  }
  throw new Error('no global section in the wasm');
}

const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'test-vectors', 'vectors.json'), 'utf8'),
).vectors;
function vec(name) {
  const v = vectors.find((x) => x.name === name);
  assert.ok(v, `missing test vector ${name}`);
  return v;
}
const H = (hex) => Buffer.from(hex, 'hex');

// ---------------------------------------------------------------------------
// The audited list (L17 "The audited list"). `line` is the `#[wasm_bindgen]`
// attribute line in beebeeb-wasm/src/lib.rs at this commit. Its length is N.
// ---------------------------------------------------------------------------
const AUDITED = [
  // Passwords, passphrases, recovery phrase, OPAQUE state/session/export keys.
  { name: 'derive_master_key', line: 16 },
  { name: 'generate_share_token', line: 30 },
  { name: 'generate_recovery_phrase', line: 140 },
  { name: 'recover_from_phrase', line: 155 },
  { name: 'opaque_registration_start', line: 166 },
  { name: 'opaque_registration_finish', line: 187 },
  { name: 'opaque_login_start', line: 198 },
  { name: 'opaque_login_finish', line: 224 },
  { name: 'evaluate_password', line: 1179 },
  { name: 'WasmBreachCheck.new', line: 1243 },
  { name: 'WasmSignupCeremony.setPassword', line: 1426 },
  { name: 'WasmSignupCeremony.setPasswordUnchecked', line: 1440 },
  { name: 'WasmSignupCeremony.beginPhrase', line: 1448 },
  { name: 'WasmSignupCeremony.confirmPhrase', line: 1478 },
  { name: 'WasmSignupCeremony.startRegistration', line: 1492 },
  { name: 'WasmSignupCeremony.finishRegistration', line: 1502 },
  { name: 'generate_recovery_pdf', line: 1627 },
  { name: 'deriveFolderLinkPassphraseStretch', line: 4320 },
  // Generic AEAD and the name/thumbnail/note surfaces.
  { name: 'encrypt_chunk', line: 54 },
  { name: 'decrypt_chunk', line: 67 },
  { name: 'encrypt_metadata', line: 84 },
  { name: 'decrypt_metadata', line: 92 },
  { name: 'decrypt_chunks', line: 106 },
  { name: 'decrypt_chunk_frame', line: 895 },
  { name: 'encrypt_name_with_chunk_format', line: 921 },
  { name: 'decrypt_name_metadata', line: 957 },
  { name: 'decrypt_file_metadata', line: 970 },
  { name: 'decrypt_file_metadata_with_key', line: 979 },
  { name: 'encrypt_thumbnail', line: 992 },
  { name: 'encrypt_thumbnail_for', line: 1002 },
  { name: 'decrypt_thumbnail', line: 1011 },
  { name: 'encrypt_note', line: 1024 },
  { name: 'encrypt_note_for', line: 1035 },
  { name: 'encrypt_name_for', line: 1061 },
  { name: 'decrypt_note', line: 1087 },
  { name: 'decrypt_name_metadata_with_key', line: 1095 },
  // Streaming content (bulk plaintext).
  { name: 'WasmChunkEncryptor.new', line: 642 },
  { name: 'WasmChunkEncryptor.withChunkSize', line: 659 },
  { name: 'WasmChunkEncryptor.pushChunk', line: 681 },
  { name: 'WasmChunkDecryptor.new', line: 815 },
  { name: 'WasmChunkDecryptor.fromFileKey', line: 826 },
  { name: 'WasmChunkDecryptor.pushFrame', line: 849 },
  // Keys: derivation, ECDH, request seals, wraps.
  { name: 'derive_file_key', line: 38 },
  { name: 'derive_x25519_private', line: 261 },
  { name: 'derive_x25519_public', line: 271 },
  { name: 'x25519_shared_secret', line: 280 },
  { name: 'derive_share_key', line: 294 },
  { name: 'compute_recovery_check', line: 303 },
  { name: 'folder_key_id', line: 317 },
  { name: 'deriveSharedFolderIndexKey', line: 330 },
  { name: 'combineFolderLinkKey', line: 348 },
  { name: 'transfer_generate_keypair', line: 383 },
  { name: 'transfer_derive_key', line: 401 },
  { name: 'transfer_derive_sas_bytes', line: 418 },
  { name: 'transfer_sas_to_words', line: 433 },
  { name: 'transfer_encrypt', line: 450 },
  { name: 'transfer_decrypt', line: 459 },
  { name: 'derive_request_wrap_key', line: 471 },
  { name: 'wrap_request_private', line: 482 },
  { name: 'unwrap_request_private', line: 508 },
  { name: 'seal_to_request', line: 527 },
  { name: 'open_request_upload', line: 553 },
  { name: 'wrapFolderChild', line: 4079 },
  { name: 'unwrapFolderChild', line: 4103 },
  { name: 'wrapOwnerFileKey', line: 4164 },
  { name: 'unwrapOwnerFileKey', line: 4173 },
  { name: 'openLegacyInviteOwnerCopy', line: 4193 },
  { name: 'wrapInviteOwnerCopy', line: 4226 },
  { name: 'unwrapInviteOwnerCopy', line: 4236 },
  { name: 'wrapFolderCustody', line: 4250 },
  { name: 'unwrapFolderCustody', line: 4260 },
  { name: 'wrapLinkOwnerKey', line: 4275 },
  { name: 'unwrapLinkOwnerKey', line: 4286 },
  { name: 'wrapLinkOwnerToken', line: 4298 },
  { name: 'unwrapLinkOwnerToken', line: 4308 },
  // Encrypted search index (key + file names).
  { name: 'WasmSearchIndex.fromEncryptedShards', line: 1848 },
  { name: 'WasmSearchIndex.encryptShards', line: 1890 },
  { name: 'WasmSearchIndex.encryptBuckets', line: 1901 },
  { name: 'WasmSearchIndex.fromEncryptedShardsWithFolderKey', line: 1914 },
  { name: 'WasmSearchIndex.encryptShardsWithFolderKey', line: 1933 },
  { name: 'WasmSearchIndex.encryptBucketsWithFolderKey', line: 1944 },
  { name: 'WasmSearchIndex.decrypt_names', line: 2023 },
];

// ---------------------------------------------------------------------------
// Fixtures: public test-vector keys plus a fixed ASCII password and a
// NON-ASCII passphrase (the case that leaves an ASCII prefix behind when a
// string is grown through realloc).
// ---------------------------------------------------------------------------
const V = {
  child: vec('folder_child_file_v1'),
  fileKey: vec('file_key_derivation'),
  gcm: vec('chunk_encrypt_decrypt'),
  meta: vec('metadata_v2_name'),
  metaKey: vec('metadata_v2_name_filekey'),
  req: vec('file_request_seal_open'),
  phrase: vec('recovery_phrase_roundtrip'),
  chunk: vec('chunk_v2_stream'),
  link: vec('folder_link_passphrase'),
  thumb: vec('thumbnail_encrypt'),
  identity: vec('x25519_identity_keypair'),
  share: vec('x25519_share_key_exchange'),
  custody: vec('folder_custody_v1'),
  invite: vec('invite_owner_copy_v1'),
  linkOwner: vec('link_owner_key_v1'),
};

const PASSWORD = 'correct horse battery staple 42';
const PASSPHRASE = 'pässwörd-ß-🔑';
const SECRET_NAME = 'quarterly-board-pack-ß.pdf';

const mk = H(V.fileKey.master_key_hex); // 32-byte master key
const fileKey = H(V.fileKey.expected_file_key_hex); // 32-byte file key
const folderKey = H(V.link.k_c_hex); // 32-byte folder key (K_c)
const childKey = H(V.child.child_key_hex); // 32-byte child key
const fileId = H(V.fileKey.file_id_hex);
const fileIdStr = V.chunk.file_id;
const itemId = V.child.item_id;
const sharedFolderId = V.child.shared_folder_id;
const plaintext = H(V.chunk.plaintext_hex);
const metadata = '{"name":"board pack ß","mime":"application/pdf"}';
const mnemonic = V.phrase.mnemonic;
const passwordBytes = Buffer.from(PASSWORD, 'utf8');
const passphraseBytes = Buffer.from(PASSPHRASE, 'utf8');
const phraseBytes = Buffer.from(mnemonic, 'utf8');
const token = V.link.token;
const tokenBytes = Buffer.from(token, 'utf8');
const v2frame = H(V.chunk.frames[0].frame_hex);
const versionId = H(V.chunk.version_id_hex);
const chunkMk = H(V.chunk.master_key_hex); // master key of the v2 chunk fixture
const chunkFileKey = H(V.chunk.file_key_hex); // its file key
const gcmFileKey = H(V.gcm.file_key_hex); // file key of the AEAD fixture

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------
function instance() {
  assert.ok(wasmExports && wasmExports.memory, 'captured instance has no memory export');
  return wasmExports;
}

let heapBaseCache = null;
function heapBase() {
  if (heapBaseCache != null) return heapBaseCache;
  const exported = instance().__heap_base;
  const base = exported && typeof exported.value === 'number' ? exported.value : readHeapBase(wasmFile());
  assert.ok(base > 1024, `implausible heap base ${base}`);
  heapBaseCache = base;
  return base;
}

function heapRegion() {
  const mem = instance().memory;
  const base = heapBase();
  const len = mem.buffer.byteLength - base;
  assert.ok(len > 0, `empty heap region (base=${base} len=${mem.buffer.byteLength})`);
  return { bytes: Buffer.from(mem.buffer, base, len), base, len };
}

const toBytes = (v) => {
  if (v == null) return null;
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  if (typeof v === 'string') return Buffer.from(v, 'utf8');
  if (Array.isArray(v)) return Buffer.concat(v.map(toBytes).filter(Boolean));
  return null;
};

// Count occurrences of each secret in the heap. 16-byte tail for secrets that
// have one, whole value for shorter ones.
function scan(secrets) {
  const { bytes } = heapRegion();
  const rows = [];
  for (const { label, bytes: b } of secrets) {
    const needle = b.length >= 16 ? b.subarray(b.length - 16) : b;
    let from = 0;
    let n = 0;
    for (;;) {
      const i = bytes.indexOf(needle, from);
      if (i < 0) break;
      n += 1;
      from = i + 1;
    }
    rows.push({ label, needle: needle.length, len: b.length, matches: n });
  }
  return { scanned: bytes.length, rows };
}

const attempt = (fn) => {
  try {
    return fn();
  } catch {
    return undefined; // a throw still exercises the argument copies
  }
};

// Fixture secrets reused by several calls.
const reqShared = H(V.share.expected_shared_secret_hex);
// High-entropy keypair for the request seals: the request vector's r_priv/r_pub
// are a repeated byte, which is a degenerate needle for a heap scan (a run of
// that byte elsewhere reads as a false match).
const reqPriv = H(V.identity.expected_x25519_private_hex);
const reqPub = H(V.identity.expected_x25519_public_hex);
const sessionId = Buffer.from('0123456789abcdef', 'utf8');
const transferKey = H(V.gcm.file_key_hex);
const reqVector = V.req;

// ---------------------------------------------------------------------------
// One runner per audited export. Each pushes every secret it hands to (or gets
// back from) the export into `s`.
// ---------------------------------------------------------------------------
const CALLS = {
  derive_master_key: (s) => {
    const salt = mk.subarray(0, 16);
    s.secret('password', PASSWORD);
    const out = wasm.derive_master_key(PASSWORD, salt);
    s.secret('master key (out)', out.key);
  },
  generate_share_token: (s) => {
    const t = wasm.generate_share_token();
    s.secret('share token (out)', t);
  },
  generate_recovery_phrase: (s) => {
    const o = wasm.generate_recovery_phrase();
    s.secret('phrase (out)', o.phrase);
    s.secret('master key (out)', o.master_key);
  },
  recover_from_phrase: (s) => {
    s.secret('phrase (in)', mnemonic);
    s.secret('master key (out)', wasm.recover_from_phrase(mnemonic));
  },
  opaque_registration_start: (s) => {
    s.secret('password (in)', passwordBytes);
    wasm.opaque_registration_start(passwordBytes);
  },
  opaque_registration_finish: (s) => {
    const start = wasm.opaque_registration_start(passwordBytes);
    s.secret('password (in)', passwordBytes);
    attempt(() => wasm.opaque_registration_finish(start.state, passwordBytes, new Uint8Array(64)));
  },
  opaque_login_start: (s) => {
    s.secret('password (in)', passwordBytes);
    wasm.opaque_login_start(passwordBytes);
  },
  opaque_login_finish: (s) => {
    const start = wasm.opaque_login_start(passwordBytes);
    s.secret('password (in)', passwordBytes);
    // No server: the finish cannot succeed offline, but its argument copies are
    // still allocated and freed inside WASM.
    attempt(() => wasm.opaque_login_finish(start.state, passwordBytes, new Uint8Array(64), 1));
  },
  evaluate_password: (s) => {
    s.secret('password (in)', PASSWORD);
    attempt(() => wasm.evaluate_password(PASSWORD, 12));
  },
  'WasmBreachCheck.new': (s) => {
    s.secret('password (in)', PASSWORD);
    const c = new wasm.WasmBreachCheck(PASSWORD);
    attempt(() => c.prefix);
    c.free();
  },
  'WasmSignupCeremony.setPassword': (s) => {
    const c = new wasm.WasmSignupCeremony(12, false, 4, false, true);
    const b = new wasm.WasmBreachCheck(PASSWORD);
    s.secret('password (in)', PASSWORD);
    attempt(() => c.setPassword(PASSWORD, PASSWORD, b));
    c.free();
    b.free();
  },
  'WasmSignupCeremony.setPasswordUnchecked': (s) => {
    const c = new wasm.WasmSignupCeremony(12, false, 4, false, true);
    s.secret('password (in)', PASSWORD);
    attempt(() => c.setPasswordUnchecked(PASSWORD, PASSWORD));
    c.free();
  },
  'WasmSignupCeremony.beginPhrase': (s) => {
    const c = new wasm.WasmSignupCeremony(12, false, 4, false, true);
    c.setPasswordUnchecked(PASSWORD, PASSWORD);
    s.secret('password (in)', PASSWORD);
    attempt(() => c.beginPhrase());
    c.free();
  },
  'WasmSignupCeremony.confirmPhrase': (s) => {
    const c = new wasm.WasmSignupCeremony(12, false, 4, false, true);
    c.setPasswordUnchecked(PASSWORD, PASSWORD);
    c.beginPhrase();
    s.secret('phrase (in)', phraseBytes);
    attempt(() => {
      const words = mnemonic.split(' ');
      const positions = c.challengePositions();
      c.confirmPhrase(positions.map((p) => words[p]));
    });
    c.free();
  },
  'WasmSignupCeremony.startRegistration': (s) => {
    const c = new wasm.WasmSignupCeremony(12, false, 4, false, true);
    c.setPasswordUnchecked(PASSWORD, PASSWORD);
    c.beginPhrase();
    s.secret('password (in)', PASSWORD);
    attempt(() => c.startRegistration());
    attempt(() => c.free());
  },
  'WasmSignupCeremony.finishRegistration': (s) => {
    const c = new wasm.WasmSignupCeremony(12, false, 4, false, true);
    c.setPasswordUnchecked(PASSWORD, PASSWORD);
    c.beginPhrase();
    s.secret('password (in)', PASSWORD);
    attempt(() => c.startRegistration());
    attempt(() => c.finishRegistration(new Uint8Array(96)));
    attempt(() => c.free());
  },
  generate_recovery_pdf: (s) => {
    const words = mnemonic.split(' ');
    s.secret('phrase (in)', phraseBytes);
    s.secret('pdf (out)', wasm.generate_recovery_pdf('Recovery', words, ['Account'], ['tester']));
  },
  deriveFolderLinkPassphraseStretch: (s) => {
    s.secret('passphrase (in)', passphraseBytes);
    s.secret('stretch (out)', wasm.deriveFolderLinkPassphraseStretch(PASSPHRASE, token));
  },

  encrypt_chunk: (s) => {
    s.secret('file key (in)', gcmFileKey);
    s.secret('plaintext (in)', plaintext);
    wasm.encrypt_chunk(gcmFileKey, plaintext);
  },
  decrypt_chunk: (s) => {
    s.secret('file key (in)', gcmFileKey);
    s.secret('plaintext (out)', wasm.decrypt_chunk(gcmFileKey, H(V.gcm.nonce_hex), H(V.gcm.ciphertext_hex)));
  },
  encrypt_metadata: (s) => {
    s.secret('file key (in)', gcmFileKey);
    s.secret('metadata (in)', metadata);
    wasm.encrypt_metadata(gcmFileKey, metadata);
  },
  decrypt_metadata: (s) => {
    const blob = wasm.encrypt_metadata(gcmFileKey, metadata);
    s.secret('file key (in)', gcmFileKey);
    s.secret('metadata (out)', wasm.decrypt_metadata(gcmFileKey, blob.nonce, blob.ciphertext));
  },
  decrypt_chunks: (s) => {
    s.secret('file key (in)', gcmFileKey);
    s.secret(
      'plaintext (out)',
      wasm.decrypt_chunks(gcmFileKey, [
        { nonce: H(V.gcm.nonce_hex), ciphertext: H(V.gcm.ciphertext_hex) },
      ]),
    );
  },
  decrypt_chunk_frame: (s) => {
    s.secret('file key (in)', chunkFileKey);
    s.secret(
      'plaintext (out)',
      wasm.decrypt_chunk_frame(chunkFileKey, fileIdStr, versionId, 0, false, 2, v2frame),
    );
  },
  encrypt_name_with_chunk_format: (s) => {
    s.secret('master key (in)', mk);
    const enc = wasm.encrypt_name_with_chunk_format(mk, fileIdStr, SECRET_NAME, 'application/pdf', 2);
    s.secret('name (in)', SECRET_NAME);
    s.secret('name_encrypted (out)', enc);
  },
  decrypt_name_metadata: (s) => {
    s.secret('master key (in)', mk);
    s.secret('name (out)', attempt(() => wasm.decrypt_name_metadata(mk, V.meta.file_id, V.meta.name_encrypted)?.name));
  },
  decrypt_file_metadata: (s) => {
    s.secret('master key (in)', mk);
    s.secret('name (out)', attempt(() => wasm.decrypt_file_metadata(mk, V.meta.file_id, V.meta.name_encrypted)?.name));
  },
  decrypt_file_metadata_with_key: (s) => {
    const fk = H(V.metaKey.file_key_hex);
    s.secret('file key (in)', fk);
    s.secret('name (out)', attempt(() => wasm.decrypt_file_metadata_with_key(fk, V.metaKey.name_encrypted)?.name));
  },
  encrypt_thumbnail: (s) => {
    const thumb = H(V.thumb.plaintext_hex);
    s.secret('file key (in)', fileKey);
    s.secret('thumbnail (in)', thumb);
    wasm.encrypt_thumbnail(fileKey, thumb);
  },
  encrypt_thumbnail_for: (s) => {
    const thumb = H(V.thumb.plaintext_hex);
    s.secret('file key (in)', fileKey);
    s.secret('thumbnail (in)', thumb);
    wasm.encrypt_thumbnail_for(fileKey, thumb, 2);
  },
  decrypt_thumbnail: (s) => {
    const fk = H(V.thumb.file_key_hex);
    const frame = Buffer.concat([H(V.thumb.nonce_hex), H(V.thumb.ciphertext_hex)]);
    s.secret('file key (in)', fk);
    s.secret('thumbnail (out)', attempt(() => wasm.decrypt_thumbnail(fk, frame)));
  },
  encrypt_note: (s) => {
    s.secret('file key (in)', fileKey);
    s.secret('note (in)', SECRET_NAME);
    wasm.encrypt_note(fileKey, SECRET_NAME);
  },
  encrypt_note_for: (s) => {
    s.secret('file key (in)', fileKey);
    s.secret('note (in)', SECRET_NAME);
    wasm.encrypt_note_for(fileKey, SECRET_NAME, 2);
  },
  encrypt_name_for: (s) => {
    s.secret('file key (in)', fileKey);
    s.secret('name (in)', SECRET_NAME);
    wasm.encrypt_name_for(fileKey, SECRET_NAME, 'application/pdf', 2);
  },
  decrypt_note: (s) => {
    s.secret('file key (in)', fileKey);
    const blob = wasm.encrypt_note(fileKey, SECRET_NAME);
    s.secret('note (out)', attempt(() => wasm.decrypt_note(fileKey, blob)));
  },
  decrypt_name_metadata_with_key: (s) => {
    const fk = H(V.metaKey.file_key_hex);
    s.secret('file key (in)', fk);
    s.secret('name (out)', attempt(() => wasm.decrypt_name_metadata_with_key(fk, V.metaKey.name_encrypted)?.name));
  },

  'WasmChunkEncryptor.new': (s) => {
    s.secret('master key (in)', chunkMk);
    const e = new wasm.WasmChunkEncryptor(chunkMk, fileIdStr, 8n, 'web');
    s.secret('plaintext (in)', plaintext.subarray(0, 8));
    attempt(() => e.pushChunk(plaintext.subarray(0, 8)));
    e.free();
  },
  'WasmChunkEncryptor.withChunkSize': (s) => {
    s.secret('master key (in)', chunkMk);
    const e = wasm.WasmChunkEncryptor.withChunkSize(chunkMk, fileIdStr, 8n, 8n);
    e.free();
  },
  'WasmChunkEncryptor.pushChunk': (s) => {
    const e = new wasm.WasmChunkEncryptor(chunkMk, fileIdStr, 8n, 'web');
    s.secret('master key (in)', chunkMk);
    s.secret('plaintext (in)', plaintext.subarray(0, 8));
    attempt(() => e.pushChunk(plaintext.subarray(0, 8)));
    e.free();
  },
  'WasmChunkDecryptor.new': (s) => {
    s.secret('master key (in)', chunkMk);
    const d = new wasm.WasmChunkDecryptor(chunkMk, fileIdStr, 2);
    s.secret('plaintext (out)', attempt(() => d.pushFrame(v2frame)));
    attempt(() => d.free());
  },
  'WasmChunkDecryptor.fromFileKey': (s) => {
    s.secret('file key (in)', chunkFileKey);
    const d = wasm.WasmChunkDecryptor.fromFileKey(chunkFileKey, fileIdStr, 2);
    d.free();
  },
  'WasmChunkDecryptor.pushFrame': (s) => {
    const d = new wasm.WasmChunkDecryptor(chunkMk, fileIdStr, 2);
    s.secret('master key (in)', chunkMk);
    s.secret('plaintext (out)', attempt(() => d.pushFrame(v2frame)));
    attempt(() => d.free());
  },

  derive_file_key: (s) => {
    s.secret('master key (in)', mk);
    s.secret('file key (out)', wasm.derive_file_key(mk, fileId));
  },
  derive_x25519_private: (s) => {
    s.secret('master key (in)', mk);
    s.secret('x25519 private (out)', wasm.derive_x25519_private(mk));
  },
  derive_x25519_public: (s) => {
    const priv = H(V.identity.expected_x25519_private_hex);
    s.secret('x25519 private (in)', priv);
    wasm.derive_x25519_public(priv);
  },
  x25519_shared_secret: (s) => {
    s.secret('x25519 private (in)', reqPriv);
    s.secret('shared secret (out)', wasm.x25519_shared_secret(reqPriv, reqPub));
  },
  derive_share_key: (s) => {
    s.secret('shared secret (in)', reqShared);
    s.secret('share key (out)', wasm.derive_share_key(reqShared, fileId));
  },
  compute_recovery_check: (s) => {
    s.secret('master key (in)', mk);
    wasm.compute_recovery_check(mk);
  },
  folder_key_id: (s) => {
    s.secret('folder key (in)', folderKey);
    wasm.folder_key_id(folderKey);
  },
  deriveSharedFolderIndexKey: (s) => {
    s.secret('folder key (in)', folderKey);
    wasm.deriveSharedFolderIndexKey(folderKey, 3);
  },
  combineFolderLinkKey: (s) => {
    s.secret('K_c (in)', folderKey);
    s.secret('stretch (in)', H(V.link.stretch_hex));
    s.secret('link key (out)', wasm.combineFolderLinkKey(folderKey, H(V.link.stretch_hex)));
  },
  transfer_generate_keypair: (s) => {
    const kp = wasm.transfer_generate_keypair();
    s.secret('transfer private (out)', kp.private);
  },
  transfer_derive_key: (s) => {
    s.secret('shared secret (in)', reqShared);
    s.secret('transfer key (out)', wasm.transfer_derive_key(reqShared, sessionId));
  },
  transfer_derive_sas_bytes: (s) => {
    s.secret('shared secret (in)', reqShared);
    s.secret('sas bytes (out)', wasm.transfer_derive_sas_bytes(reqShared, sessionId));
  },
  transfer_sas_to_words: (s) => {
    const sas = H(V.gcm.nonce_hex).subarray(0, 4);
    s.secret('sas bytes (in)', sas);
    wasm.transfer_sas_to_words(sas);
  },
  transfer_encrypt: (s) => {
    s.secret('transfer key (in)', transferKey);
    s.secret('plaintext (in)', plaintext);
    wasm.transfer_encrypt(transferKey, plaintext);
  },
  transfer_decrypt: (s) => {
    const blob = wasm.transfer_encrypt(transferKey, plaintext);
    s.secret('transfer key (in)', transferKey);
    s.secret('plaintext (out)', wasm.transfer_decrypt(transferKey, blob));
  },
  derive_request_wrap_key: (s) => {
    s.secret('master key (in)', H(reqVector.master_key_hex));
    wasm.derive_request_wrap_key(H(reqVector.master_key_hex), H(reqVector.request_id_hex));
  },
  wrap_request_private: (s) => {
    const mkReq = H(reqVector.master_key_hex);
    s.secret('master key (in)', mkReq);
    s.secret('request private (in)', reqPriv);
    const o = wasm.wrap_request_private(mkReq, H(reqVector.request_id_hex), reqPriv);
    s.secret('wrapped private (out)', o.wrapped);
  },
  unwrap_request_private: (s) => {
    const mkReq = H(reqVector.master_key_hex);
    const w = wasm.wrap_request_private(mkReq, H(reqVector.request_id_hex), reqPriv);
    s.secret('master key (in)', mkReq);
    s.secret(
      'request private (out)',
      wasm.unwrap_request_private(mkReq, H(reqVector.request_id_hex), w.wrapped, w.nonce),
    );
  },
  seal_to_request: (s) => {
    s.secret('content key (in)', chunkFileKey);
    const o = wasm.seal_to_request(reqPub, H(reqVector.file_id_hex), chunkFileKey);
    s.secret('wrapped key (out)', o.wrapped_key);
  },
  open_request_upload: (s) => {
    const o = wasm.seal_to_request(reqPub, H(reqVector.file_id_hex), chunkFileKey);
    s.secret('request private (in)', reqPriv);
    s.secret('content key (out)', wasm.open_request_upload(reqPriv, o.e_pub, H(reqVector.file_id_hex), o.wrapped_key));
  },
  wrapFolderChild: (s) => {
    s.secret('folder key (in)', folderKey);
    s.secret('child key (in)', childKey);
    s.secret(
      'wrapped child (out)',
      wasm.wrapFolderChild(folderKey, sharedFolderId, itemId, V.child.kind, childKey),
    );
  },
  unwrapFolderChild: (s) => {
    const frame = wasm.wrapFolderChild(folderKey, sharedFolderId, itemId, V.child.kind, childKey);
    s.secret('folder key (in)', folderKey);
    s.secret('child key (out)', wasm.unwrapFolderChild(folderKey, sharedFolderId, itemId, V.child.kind, frame));
  },
  wrapOwnerFileKey: (s) => {
    const v = V.custody;
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('file key (in)', fileKey);
    s.secret(
      'wrapped file key (out)',
      wasm.wrapOwnerFileKey(H(v.master_key_hex), V.chunk.file_id, fileKey),
    );
  },
  unwrapOwnerFileKey: (s) => {
    const v = V.custody;
    const frame = wasm.wrapOwnerFileKey(H(v.master_key_hex), V.chunk.file_id, fileKey);
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('file key (out)', attempt(() => wasm.unwrapOwnerFileKey(H(v.master_key_hex), V.chunk.file_id, frame)));
  },
  openLegacyInviteOwnerCopy: (s) => {
    const v = V.invite;
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('folder key (out)', attempt(() =>
      wasm.openLegacyInviteOwnerCopy(H(v.master_key_hex), v.record_id, H(v.wrapped_hex), []),
    ));
  },
  wrapInviteOwnerCopy: (s) => {
    const v = V.custody;
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('folder key (in)', folderKey);
    s.secret('wrapped (out)', wasm.wrapInviteOwnerCopy(H(v.master_key_hex), v.record_id, folderKey));
  },
  unwrapInviteOwnerCopy: (s) => {
    const v = V.custody;
    const frame = wasm.wrapInviteOwnerCopy(H(v.master_key_hex), v.record_id, folderKey);
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('folder key (out)', attempt(() => wasm.unwrapInviteOwnerCopy(H(v.master_key_hex), v.record_id, frame)));
  },
  wrapFolderCustody: (s) => {
    const v = V.custody;
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('folder key (in)', folderKey);
    s.secret('wrapped custody (out)', wasm.wrapFolderCustody(H(v.master_key_hex), v.record_id, folderKey));
  },
  unwrapFolderCustody: (s) => {
    const v = V.custody;
    const frame = wasm.wrapFolderCustody(H(v.master_key_hex), v.record_id, folderKey);
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('folder key (out)', attempt(() => wasm.unwrapFolderCustody(H(v.master_key_hex), v.record_id, frame)));
  },
  wrapLinkOwnerKey: (s) => {
    const v = V.linkOwner;
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('link key (in)', folderKey);
    s.secret('wrapped link key (out)', wasm.wrapLinkOwnerKey(H(v.master_key_hex), v.record_id, folderKey));
  },
  unwrapLinkOwnerKey: (s) => {
    const v = V.linkOwner;
    const frame = wasm.wrapLinkOwnerKey(H(v.master_key_hex), v.record_id, folderKey);
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('link key (out)', attempt(() => wasm.unwrapLinkOwnerKey(H(v.master_key_hex), v.record_id, frame)));
  },
  wrapLinkOwnerToken: (s) => {
    const v = V.linkOwner;
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('token (in)', tokenBytes);
    s.secret('wrapped token (out)', wasm.wrapLinkOwnerToken(H(v.master_key_hex), v.record_id, tokenBytes));
  },
  unwrapLinkOwnerToken: (s) => {
    const v = V.linkOwner;
    const frame = wasm.wrapLinkOwnerToken(H(v.master_key_hex), v.record_id, tokenBytes);
    s.secret('master key (in)', H(v.master_key_hex));
    s.secret('token (out)', attempt(() => wasm.unwrapLinkOwnerToken(H(v.master_key_hex), v.record_id, frame)));
  },

  'WasmSearchIndex.fromEncryptedShards': (s) => {
    const idx = wasm.WasmSearchIndex.build([{ fileId: itemId, name: SECRET_NAME }], 64);
    const shards = idx.encryptShards(mk);
    s.secret('master key (in)', mk);
    const back = wasm.WasmSearchIndex.fromEncryptedShards(mk, shards, 64);
    attempt(() => back.free());
    idx.free();
  },
  'WasmSearchIndex.encryptShards': (s) => {
    const idx = wasm.WasmSearchIndex.build([{ fileId: itemId, name: SECRET_NAME }], 64);
    s.secret('master key (in)', mk);
    s.secret('name (in)', SECRET_NAME);
    idx.encryptShards(mk);
    idx.free();
  },
  'WasmSearchIndex.encryptBuckets': (s) => {
    const idx = wasm.WasmSearchIndex.build([{ fileId: itemId, name: SECRET_NAME }], 64);
    s.secret('master key (in)', mk);
    s.secret('name (in)', SECRET_NAME);
    idx.encryptBuckets(mk, [0, 1]);
    idx.free();
  },
  'WasmSearchIndex.fromEncryptedShardsWithFolderKey': (s) => {
    const idx = wasm.WasmSearchIndex.build([{ fileId: itemId, name: SECRET_NAME }], 64);
    const shards = idx.encryptShardsWithFolderKey(folderKey);
    s.secret('folder key (in)', folderKey);
    const back = wasm.WasmSearchIndex.fromEncryptedShardsWithFolderKey(folderKey, shards, 64);
    attempt(() => back.free());
    idx.free();
  },
  'WasmSearchIndex.encryptShardsWithFolderKey': (s) => {
    const idx = wasm.WasmSearchIndex.build([{ fileId: itemId, name: SECRET_NAME }], 64);
    s.secret('folder key (in)', folderKey);
    s.secret('name (in)', SECRET_NAME);
    idx.encryptShardsWithFolderKey(folderKey);
    idx.free();
  },
  'WasmSearchIndex.encryptBucketsWithFolderKey': (s) => {
    const idx = wasm.WasmSearchIndex.build([{ fileId: itemId, name: SECRET_NAME }], 64);
    s.secret('folder key (in)', folderKey);
    s.secret('name (in)', SECRET_NAME);
    idx.encryptBucketsWithFolderKey(folderKey, [0, 1]);
    idx.free();
  },
  'WasmSearchIndex.decrypt_names': (s) => {
    const enc = wasm.encrypt_name_with_chunk_format(mk, itemId, SECRET_NAME, 'application/pdf', 2);
    s.secret('master key (in)', mk);
    s.secret('name (out)', attempt(() => wasm.decrypt_names(mk, [{ fileId: itemId, nameEncrypted: enc }])?.[0]?.name));
  },
};

test('heap scan: no raw secret bytes in the WASM heap after an export returns', () => {
  // N and the scanner are real: the list is non-empty, every entry has a call,
  // and the scanner sees a secret that is genuinely alive in the heap.
  assert.ok(AUDITED.length >= 60, `audited list too short: N=${AUDITED.length}`);
  for (const e of AUDITED) {
    assert.ok(CALLS[e.name], `no call implemented for audited export ${e.name}`);
  }
  assert.equal(Object.keys(CALLS).length, AUDITED.length, 'CALLS and AUDITED must cover the same exports');
  const base = heapBase();
  console.log(`# heap base ${base}, heap ${instance().memory.buffer.byteLength - base} bytes, N=${AUDITED.length}`);

  // Positive control: while a chunk encryptor is alive its master key is a live
  // allocation, so the scanner MUST find the 16-byte tail. This proves the scan
  // region and the needle logic actually see heap bytes.
  // A ceremony keeps the submitted password in `Zeroizing<String>` until
  // registration, so while it is alive the password is a live heap allocation
  // and the scanner MUST find its tail. Used nowhere else in this file.
  const controlPassword = 'control-password-2254-ß';
  const ceremony = new wasm.WasmSignupCeremony(8, false, 12, false, true);
  ceremony.setPasswordUnchecked(controlPassword, controlPassword);
  const liveScan = scan([{ label: 'control password (live)', bytes: Buffer.from(controlPassword, 'utf8') }]);
  ceremony.free();
  const afterFree = scan([{ label: 'control password (freed)', bytes: Buffer.from(controlPassword, 'utf8') }]);
  console.log(
    `# control: live in a ceremony ${liveScan.rows[0].matches} (must be >0), after free ${afterFree.rows[0].matches} (0 when the allocator wipes)`,
  );
  assert.ok(liveScan.rows[0].matches > 0, 'scanner cannot see a live secret: the heap region or needle logic is wrong');

  let exercised = 0;
  let totalBytes = 0;
  let totalMatches = 0;
  for (const entry of AUDITED) {
    const secrets = [];
    const s = {
      secret(label, value) {
        const b = toBytes(value);
        if (b && b.length > 0) secrets.push({ label, bytes: b });
      },
    };
    CALLS[entry.name](s);
    exercised += 1;
    const result = scan(secrets);
    totalBytes += result.scanned;
    const matches = result.rows.reduce((n, r) => n + r.matches, 0);
    totalMatches += matches;
    const detail = result.rows.map((r) => `${r.label}=${r.matches}`).join(' ');
    console.log(
      `# lib.rs:${entry.line} ${entry.name}: scanned ${result.scanned} bytes, ${secrets.length} secrets, matches ${matches} (${detail})`,
    );
  }

  console.log(`# exercised ${exercised}/${AUDITED.length} exports, ${totalBytes} bytes scanned, ${totalMatches} matches`);
  assert.equal(exercised, AUDITED.length, `exercised ${exercised} exports, expected N=${AUDITED.length}`);
  assert.ok(totalBytes > 0, 'no bytes were scanned: the scan is vacuous');
  assert.equal(totalMatches, 0, `${totalMatches} raw secret matches left in the WASM heap`);
});
