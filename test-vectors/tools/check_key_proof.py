#!/usr/bin/env python3
"""Independent check of the published one-time key-proof vector."""

import json
import struct
import sys

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def raw_public(private: x25519.X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def field(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def main(path: str) -> None:
    with open(path, "r", encoding="utf-8") as handle:
        root = json.load(handle)
    vector = next(v for v in root["vectors"] if v["name"] == "key_proof_session_v1")

    master = bytes.fromhex(vector["master_key_hex"])
    account_private_bytes = hkdf(master, b"beebeeb-x25519-identity")
    account_private = x25519.X25519PrivateKey.from_private_bytes(account_private_bytes)
    account_public = raw_public(account_private)

    server_private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(vector["server_private_hex"]))
    server_public = raw_public(server_private)
    assert account_public == bytes.fromhex(vector["account_public_hex"])
    assert server_public == bytes.fromhex(vector["server_public_hex"])

    shared = account_private.exchange(server_private.public_key())
    mac_key = hkdf(shared, vector["key_info"].encode("ascii"))
    transcript = (
        vector["transcript_domain"].encode("ascii")
        + vector["purpose"].encode("ascii")
        + field(bytes.fromhex(vector["session_id_hex"]))
        + field(bytes.fromhex(vector["account_id_hex"]))
        + bytes.fromhex(vector["nonce_hex"])
        + account_public
        + server_public
    )
    check = hmac.HMAC(mac_key, hashes.SHA256())
    check.update(transcript)
    assert check.finalize() == bytes.fromhex(vector["expected_response_hex"])
    print("key-proof vector: ok")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "test-vectors/vectors.json")
