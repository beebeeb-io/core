#!/usr/bin/env python3
"""Independently open and validate the protected metadata known answer."""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[1] / "vectors.json"
    document = json.loads(path.read_text())
    vector = next(row for row in document["vectors"] if row["name"] == "metadata_v2_name")

    master = bytes.fromhex(vector["master_key_hex"])
    file_id = vector["file_id"].encode()
    file_key = hkdf(master, b"beebeeb-file-key-v1" + file_id)
    assert file_key.hex() == vector["file_key_hex"]
    name_key = hkdf(file_key, b"beebeeb/name/v1")
    assert name_key.hex() == vector["name_key_hex"]

    envelope = json.loads(vector["name_encrypted"])
    nonce = bytes(envelope["nonce"])
    ciphertext = bytes(envelope["ciphertext"])
    metadata = json.loads(AESGCM(name_key).decrypt(nonce, ciphertext, None))

    assert metadata == {
        "chunk_format": 2,
        "mime_type": vector["expected_mime_type"],
        "name": vector["expected_name"],
        "version_counter": vector["expected_version_counter"],
        "version_id": vector["expected_version_id_hex"],
    }
    assert len(bytes.fromhex(metadata["version_id"])) == 12
    assert metadata["version_counter"] > 0
    print("protected metadata vector: ok")


if __name__ == "__main__":
    main()
