#!/usr/bin/env python3
"""Generate test-vectors/screen_lock.json: the screen-lock check record (two-level lock contract,
docs/superpowers/specs/2026-11-13-two-level-lock-design.md, section 3.2).

An independent implementation of the contract text, not a port of the Rust: the Argon2id run is
the reference C library (argon2-cffi), HKDF and AES-GCM are `cryptography`.

    stretch   = Argon2id v19 (password bytes, salt, m = 256 MiB, t = 4, p = 2, 32 bytes out,
                              associated data = "beebeeb/screen-lock/v1/stretch")
    check_key = HKDF-SHA256 (ikm = stretch, no salt, info = "beebeeb/screen-lock/v1/key", 32 bytes)
    sealed    = AES-256-GCM (check_key, nonce, token,
                             aad = "beebeeb/screen-lock/v1" || u32 BE len || owner id (UTF-8) || header)
    header    = version (1) || pepper kind (0) || password counter (u64 BE) || salt (32)
    record    = header (42) || nonce (12) || ciphertext (32) || tag (16)          = 102 bytes

`master_key_stretch` is plain Argon2id (no associated data) over the same password and salt: the
value the labelled stretch must never equal. The salts, nonces and tokens are fixed public test
bytes; a real record takes all three from the OS random source.
Rows are added HERE, never in the JSON: the drift guard fails on a hand edit.

    python3 test-vectors/tools/make_screen_lock_vectors.py test-vectors/screen_lock.json
    python3 test-vectors/tools/make_screen_lock_vectors.py --check test-vectors/screen_lock.json
    python3 test-vectors/tools/make_screen_lock_vectors.py --self-test test-vectors/screen_lock.json

--check exits 1 unless the file is byte for byte what this script writes. --self-test exits 0
only if --check accepts the file and rejects a copy with one hex digit of the first record changed.
"""
import json
import re
import struct
import sys
import tempfile

from argon2.low_level import ARGON2_VERSION, Type, core, error_to_str, ffi, lib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

STRETCH_LABEL = b"beebeeb/screen-lock/v1/stretch"
KEY_INFO = b"beebeeb/screen-lock/v1/key"
AAD_DOMAIN = b"beebeeb/screen-lock/v1"
MEMORY_KIB = 256 * 1024
ITERATIONS = 4
LANES = 2


def argon2id(password, salt, associated_data):
    out = ffi.new("uint8_t[]", 32)
    pwd = ffi.new("uint8_t[]", password)
    salt_c = ffi.new("uint8_t[]", salt)
    ad = ffi.new("uint8_t[]", associated_data) if associated_data else ffi.NULL
    ctx = ffi.new(
        "argon2_context *",
        {
            "out": out,
            "outlen": 32,
            "pwd": pwd,
            "pwdlen": len(password),
            "salt": salt_c,
            "saltlen": len(salt),
            "secret": ffi.NULL,
            "secretlen": 0,
            "ad": ad,
            "adlen": len(associated_data),
            "t_cost": ITERATIONS,
            "m_cost": MEMORY_KIB,
            "lanes": LANES,
            "threads": LANES,
            "version": ARGON2_VERSION,
            "allocate_cbk": ffi.NULL,
            "free_cbk": ffi.NULL,
            "flags": lib.ARGON2_DEFAULT_FLAGS,
        },
    )
    status = core(ctx, Type.ID.value)
    if status != lib.ARGON2_OK:
        sys.exit("argon2id failed: " + error_to_str(status))
    return bytes(ffi.buffer(out, 32))


def row(name, password, owner, counter, salt, nonce, token):
    pw = password.encode("utf-8")
    stretch = argon2id(pw, salt, STRETCH_LABEL)
    check_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=KEY_INFO).derive(stretch)
    header = bytes([1, 0]) + struct.pack(">Q", counter) + salt
    owner_bytes = owner.encode("utf-8")
    aad = AAD_DOMAIN + struct.pack(">I", len(owner_bytes)) + owner_bytes + header
    sealed = AESGCM(check_key).encrypt(nonce, token, aad)
    record = header + nonce + sealed
    assert len(record) == 102
    return {
        "name": name,
        "password": password,
        "owner": owner,
        "password_counter": counter,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "token": token.hex(),
        "stretch": stretch.hex(),
        "master_key_stretch": argon2id(pw, salt, b"").hex(),
        "record": record.hex(),
    }


def document():
    return {
        "format": "beebeeb/screen-lock/v1",
        "generator": "test-vectors/tools/make_screen_lock_vectors.py",
        "argon2id": {"version": 19, "memory_kib": MEMORY_KIB, "iterations": ITERATIONS, "lanes": LANES},
        "records": [
            row(
                "ascii password, counter 0",
                "correct horse battery staple",
                "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01",
                0,
                bytes(range(32)),
                bytes(range(0x40, 0x4C)),
                bytes(range(0x80, 0xA0)),
            ),
            row(
                "non-ascii password kept as typed (no normalization), a large counter",
                "paṩswörd ☃",
                "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12",
                0x0102030405060708,
                bytes([0xA5]) * 32,
                bytes([0x5A]) * 12,
                bytes([0xC3]) * 32,
            ),
        ],
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
        print(argv[2] + " is not what make_screen_lock_vectors.py writes", file=sys.stderr)
        return 1
    if len(argv) == 3 and argv[1] == "--self-test":
        expected = rendered()
        with open(argv[2], encoding="utf-8", newline="") as f:
            text = f.read()
        if text != expected:
            print("self-test: the committed file does not match its generator: fix that first", file=sys.stderr)
            return 1
        match = re.search(r'("record":\s*")([0-9a-f])', text)
        if match is None:
            print('self-test: no "record" row to edit', file=sys.stderr)
            return 1
        digit = "%x" % ((int(match.group(2), 16) + 1) % 16)
        edited = text[: match.start(2)] + digit + text[match.end(2) :]
        if edited == text:
            print("self-test: the edit changed nothing", file=sys.stderr)
            return 1
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
