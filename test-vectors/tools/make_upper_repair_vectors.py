#!/usr/bin/env python3
"""Independently recompute the SF-0002 upper-repair vectors and assert they match.

Requires Python `cryptography`. This script never calls Rust or reads Rust
output: it derives every key, seals the name envelope and the v1 content frames
with HKDF-SHA256 + AES-256-GCM, and compares the result field by field with
`test-vectors/vectors.json` (written by core's bless test). A mismatch exits
non-zero.

Only public, fixed test keys are used. Usage: python3 <script> [vectors.json]
"""
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER = bytes(range(0x40, 0x60))
FILE_ID = "5f0c2a9e-3b1d-4c7e-9a2f-6d8e1b4c7a30"
FILE_KEY_INFO = b"beebeeb-file-key-v1"
TAG = 16


def hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def file_key(id_bytes: bytes) -> bytes:
    return hkdf(MASTER, FILE_KEY_INFO + id_bytes)


def frame(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def name_envelope(key: bytes, nonce: bytes, name: str, mime: str) -> str:
    # The vector's pin is Unrecorded -> V1Legacy -> MetadataSeal::Legacy, i.e.
    # the envelope is sealed under the RAW per-file key (no AAD), not the name
    # subkey that v2-pinned names use.
    # serde_json's map is a BTreeMap (no preserve_order), so keys are sorted.
    plaintext = json.dumps(
        {"mime_type": mime, "name": name}, separators=(",", ":"), sort_keys=True
    ).encode()
    raw = frame(key, nonce, plaintext)
    return json.dumps(
        {
            "cipher_suite": "V1Aes256Gcm",
            "nonce": list(raw[:12]),
            "ciphertext": list(raw[12:]),
        },
        separators=(",", ":"),
    )


def expected_upper_repair() -> dict:
    upper = FILE_ID.upper()
    key = file_key(upper.encode())
    name_nonce = bytes([0x5E]) * 12
    content = b"SF-0002 read-only repair content"
    content_nonce = bytes([0x6E]) * 12
    return {
        "master_key_hex": MASTER.hex(),
        "file_id": FILE_ID,
        "file_id_upper": upper,
        "expected_name": "uppercase-repair.pdf",
        "expected_mime_type": "application/pdf",
        "expected_convention": "upper_repair",
        "expected_key_hex": key.hex(),
        "name_encrypted": name_envelope(key, name_nonce, "uppercase-repair.pdf", "application/pdf"),
        "content_plaintext_hex": content.hex(),
        "content_nonce_hex": content_nonce.hex(),
        "content_frame_hex": frame(key, content_nonce, content).hex(),
    }


def expected_split() -> dict:
    upper = FILE_ID.upper()
    upper_key = file_key(upper.encode())
    lower_key = file_key(FILE_ID.encode())
    name_nonce = bytes([0x5F]) * 12
    v1_plaintext = b"SF-0002 split content version 1"
    v1_nonce = bytes([0x6F]) * 12
    v2_plaintext = b"SF-0002 split content version 2"
    v2_nonce = bytes([0x7F]) * 12
    return {
        "master_key_hex": MASTER.hex(),
        "file_id": FILE_ID,
        "file_id_upper": upper,
        "expected_name": "split-repair.pdf",
        "expected_mime_type": "application/pdf",
        "expected_name_convention": "upper_repair",
        "expected_name_key_hex": upper_key.hex(),
        "name_encrypted": name_envelope(upper_key, name_nonce, "split-repair.pdf", "application/pdf"),
        "content_v1_plaintext_hex": v1_plaintext.hex(),
        "content_v1_nonce_hex": v1_nonce.hex(),
        "content_v1_frame_hex": frame(upper_key, v1_nonce, v1_plaintext).hex(),
        "expected_content_v1_convention": "upper_repair",
        "expected_content_v1_key_hex": upper_key.hex(),
        "content_v2_plaintext_hex": v2_plaintext.hex(),
        "content_v2_nonce_hex": v2_nonce.hex(),
        "content_v2_frame_hex": frame(lower_key, v2_nonce, v2_plaintext).hex(),
        "expected_content_v2_convention": "string",
        "expected_content_v2_key_hex": lower_key.hex(),
    }


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[1] / "vectors.json"
    vectors = {v["name"]: v for v in json.loads(path.read_text())["vectors"]}
    checked = 0
    for name, expected in (
        ("upper_repair_v1", expected_upper_repair()),
        ("upper_repair_split_v1", expected_split()),
    ):
        row = vectors[name]
        for field, value in expected.items():
            assert row[field] == value, f"{name}.{field}: python {value!r} != published {row[field]!r}"
            checked += 1
        # Every byte-bearing field must carry enough bytes for a real frame.
        for field, value in row.items():
            if field.endswith("_frame_hex") and field.startswith("content"):
                assert len(value) >= (12 + TAG) * 2, f"{name}.{field} is not a nonce||ciphertext||tag frame"
        print(f"{name}: {len(expected)} fields match the independent derivation")
    print(f"upper-repair vectors checked: 2; fields asserted: {checked}")


if __name__ == "__main__":
    main()
