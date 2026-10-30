#!/usr/bin/env python3
"""Independently generate the L8 owner-file KAT; preserve every other byte.

Requires Python cryptography. No Rust implementation or generated output is run.
Only public, fixed test keys are used. Usage: python3 <script> [vectors.json]
"""
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def owner_vector():
    master = bytes(range(32))
    child = bytes(range(0xA0, 0xC0))
    item = "11111111-1111-8111-8111-111111111111"
    nonce = bytes(range(12))
    context = b"beebeeb-owner-file-key-v1" + item.encode("utf-8")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(master)
    frame = nonce + AESGCM(key).encrypt(nonce, child, context)
    return {
        "child_key_hex": child.hex(),
        "expected_frame_hex": frame.hex(),
        "file_id": item,
        "folder_id": "22222222-2222-4222-8222-222222222222",
        "folder_key_hex": bytes(range(0x80, 0xA0)).hex(),
        "master_key_hex": master.hex(),
        "name": "owner_wrapped_file_key",
        "nonce_hex": nonce.hex(),
        "note": "L8 owner file key: HKDF-SHA256(master, domain || canonical item ID string), same context as AAD; independent Python cryptography KAT.",
    }


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[1] / "vectors.json"
    text = path.read_text()
    doc = json.loads(text)
    rows = [v for v in doc["vectors"] if v["name"] == "owner_wrapped_file_key"]
    assert len(rows) == 1
    old = json.dumps(rows[0], ensure_ascii=False, indent=2, sort_keys=True)
    old = "\n".join("    " + line for line in old.splitlines())
    new = json.dumps(owner_vector(), ensure_ascii=False, indent=2, sort_keys=True)
    new = "\n".join("    " + line for line in new.splitlines())
    assert text.count(old) == 1, "expected exactly one owner vector block"
    path.write_text(text.replace(old, new))
    updated = json.loads(path.read_text())
    unchanged = [v for v in doc["vectors"] if v["name"] != "owner_wrapped_file_key"]
    assert unchanged == [v for v in updated["vectors"] if v["name"] != "owner_wrapped_file_key"]
    print(f"owner vectors generated: 1; other vectors preserved: {len(unchanged)}")


if __name__ == "__main__":
    main()
