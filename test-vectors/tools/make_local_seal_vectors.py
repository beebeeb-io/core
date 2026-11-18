#!/usr/bin/env python3
"""Generate test-vectors/local_seal.json: the recovery snapshot and the scratch stream of
beebeeb_core::local_seal (design note docs/superpowers/specs/2026-11-18-local-snapshot-and-scratch-seal.md).

An independent implementation of the note, not a port of the Rust: HKDF and AES-GCM are `cryptography`.

    snapshot_key = HKDF-SHA256 (ikm = account key, no salt, info = "beebeeb-local-snapshot-v1" || file id UTF-8)
    header       = "BBSN" || 1 || kind || i64 BE base_version || i64 BE saved_at                       (22)
    aad          = "beebeeb-local-snapshot-aad-v1" || u32 BE len(file id) || file id
                   || i64 BE base_version || i64 BE saved_at || kind || 1
    sealed       = header || nonce(12) || AES-256-GCM (snapshot_key, nonce, plaintext, aad)  (plaintext + 50 bytes)

    file_key     = HKDF-SHA256 (ikm = scratch key, no salt, info = "beebeeb-scratch-chunk-key-v1" || scratch id)
    header       = "BBSC" || 1 || purpose || u32 BE chunk size || scratch id (16)                      (26)
    frame i      = nonce(12) || AES-256-GCM (file_key, nonce, chunk, aad) with
                   aad = "beebeeb-scratch-chunk-aad-v1" || header || u32 BE i || is_final
                   every frame holds chunk-size bytes except the last, which holds 1..=chunk bytes
                   (an exact multiple ends in one full final frame); an empty file is one empty final frame

Keys, ids and nonces are fixed public test bytes; a real seal takes nonces and the scratch key from the OS
random source. Rows are added HERE, never in the JSON: the drift guard fails on a hand edit.

    python3 test-vectors/tools/make_local_seal_vectors.py test-vectors/local_seal.json
    python3 test-vectors/tools/make_local_seal_vectors.py --check test-vectors/local_seal.json
    python3 test-vectors/tools/make_local_seal_vectors.py --self-test test-vectors/local_seal.json
"""
import hashlib
import json
import re
import struct
import sys
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SNAPSHOT_KEY_LABEL = b"beebeeb-local-snapshot-v1"
SNAPSHOT_AAD_LABEL = b"beebeeb-local-snapshot-aad-v1"
SCRATCH_KEY_LABEL = b"beebeeb-scratch-chunk-key-v1"
SCRATCH_AAD_LABEL = b"beebeeb-scratch-chunk-aad-v1"
CHUNK = 64 * 1024

MASTER_KEY = bytes(range(32))
SCRATCH_KEY = bytes(range(0x20, 0x40))
SCRATCH_ID = bytes(range(0xC0, 0xD0))
OWNER_ID = "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01"
FOREIGN_ID = "11111111-1111-8111-8111-111111111111"


def hkdf(ikm, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def snapshot_row(name, file_id, kind, base_version, saved_at, plaintext, nonce):
    fid = file_id.encode("utf-8")
    key = hkdf(MASTER_KEY, SNAPSHOT_KEY_LABEL + fid)
    header = b"BBSN" + bytes([1, kind]) + struct.pack(">qq", base_version, saved_at)
    aad = (SNAPSHOT_AAD_LABEL + struct.pack(">I", len(fid)) + fid
           + struct.pack(">qq", base_version, saved_at) + bytes([kind, 1]))
    sealed = header + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    assert len(sealed) == len(plaintext) + 50
    return {
        "name": name,
        "file_id": file_id,
        "kind": kind,
        "base_version": base_version,
        "saved_at": saved_at,
        "plaintext": plaintext.hex(),
        "nonce": nonce.hex(),
        "snapshot_key": key.hex(),
        "aad": aad.hex(),
        "header": header.hex(),
        "sealed": sealed.hex(),
    }


def pattern(n):
    return bytes((i * 7 + 3) % 251 for i in range(n))


def scratch_row(name, purpose, n):
    header = b"BBSC" + bytes([1, purpose]) + struct.pack(">I", CHUNK) + SCRATCH_ID
    file_key = hkdf(SCRATCH_KEY, SCRATCH_KEY_LABEL + SCRATCH_ID)
    data = pattern(n)
    chunks = [data[i:i + CHUNK] for i in range(0, n, CHUNK)] or [b""]
    out = header
    frames = []
    for i, chunk in enumerate(chunks):
        final = i == len(chunks) - 1
        nonce = bytes([0xA0 + i]) * 12
        aad = SCRATCH_AAD_LABEL + header + struct.pack(">I", i) + bytes([1 if final else 0])
        frame = nonce + AESGCM(file_key).encrypt(nonce, chunk, aad)
        out += frame
        frames.append({"index": i, "final": final, "nonce": nonce.hex(), "aad": aad.hex(),
                       "plain_len": len(chunk), "frame_len": len(frame)})
    row = {
        "name": name,
        "purpose": purpose,
        "plaintext_len": n,
        "file_key": file_key.hex(),
        "header": header.hex(),
        "frames": frames,
        "file_len": len(out),
        "file_sha256": hashlib.sha256(out).hexdigest(),
    }
    if n <= 1:
        row["file"] = out.hex()
    return row


def document():
    return {
        "format": "beebeeb/local-seal/v1",
        "generator": "test-vectors/tools/make_local_seal_vectors.py",
        "snapshot": {
            "master_key": MASTER_KEY.hex(),
            "records": [
                snapshot_row("empty docx, owner id", OWNER_ID, 1, 0, 0, b"", bytes([0x40 + i for i in range(12)])),
                snapshot_row("one byte xlsx, owner id", OWNER_ID, 2, 7, 1700000000, b"\x42", bytes([0x50 + i for i in range(12)])),
                snapshot_row("100 bytes pptx, owner id", OWNER_ID, 3, 123456789, 1763000000,
                             bytes((i * 3 + 1) % 256 for i in range(100)), bytes([0x60 + i for i in range(12)])),
                snapshot_row("100 bytes docx, foreign id", FOREIGN_ID, 1, 2, 1763000001,
                             bytes((i * 5 + 2) % 256 for i in range(100)), bytes([0x70 + i for i in range(12)])),
            ],
        },
        "scratch": {
            "scratch_key": SCRATCH_KEY.hex(),
            "scratch_id": SCRATCH_ID.hex(),
            "chunk_size": CHUNK,
            "plaintext": "byte i is (i * 7 + 3) mod 251",
            "files": [
                scratch_row("empty", 1, 0),
                scratch_row("one byte", 2, 1),
                scratch_row("chunk minus one", 1, CHUNK - 1),
                scratch_row("exact chunk: one full final frame", 2, CHUNK),
                scratch_row("chunk plus one", 1, CHUNK + 1),
                scratch_row("three exact chunks: three full frames", 2, 3 * CHUNK),
            ],
        },
    }


def rendered():
    return json.dumps(document(), indent=2, ensure_ascii=True) + "\n"


def check(path, expected):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read() == expected


def main(argv):
    if len(argv) == 2 and not argv[1].startswith("-"):
        with open(argv[1], "w", encoding="utf-8", newline="") as f:
            f.write(rendered())
        return 0
    if len(argv) == 3 and argv[1] == "--check":
        if check(argv[2], rendered()):
            print(argv[2] + " matches its generator")
            return 0
        print(argv[2] + " is not what make_local_seal_vectors.py writes", file=sys.stderr)
        return 1
    if len(argv) == 3 and argv[1] == "--self-test":
        expected = rendered()
        with open(argv[2], encoding="utf-8", newline="") as f:
            text = f.read()
        if text != expected:
            print("self-test: the committed file does not match its generator: fix that first", file=sys.stderr)
            return 1
        match = re.search(r'("sealed":\s*")([0-9a-f])', text)
        if match is None:
            print('self-test: no "sealed" row to edit', file=sys.stderr)
            return 1
        digit = "%x" % ((int(match.group(2), 16) + 1) % 16)
        edited = text[: match.start(2)] + digit + text[match.end(2):]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", suffix=".json") as copy:
            copy.write(edited)
            copy.flush()
            if check(copy.name, expected):
                print("self-test: --check accepted an edited record: the check cannot go red", file=sys.stderr)
                return 1
        print("self-test: an edited record is rejected, the committed file is accepted")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
