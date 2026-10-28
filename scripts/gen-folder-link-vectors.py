#!/usr/bin/env python3
"""Independent 2237c vectors (argon2-cffi + cryptography, never core output).

Print the two families, or update only those families and the version with
--write. All inputs below are public, deterministic known-answer fixtures.
"""

import argparse
import base64
import hashlib
import json
import unicodedata
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def vectors():
    wrapper = bytes(range(0x40, 0x60))
    inner = bytes(range(0x60, 0x80))
    nonce = bytes(range(12))
    token = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")
    passphrase = "folder café 2237"
    kc = bytes(range(0x80, 0xA0))
    salt = hashlib.sha256(
        token.encode("utf-8") + b"beebeeb-folder-link-passphrase-v1"
    ).digest()[:16]
    stretch = hash_secret_raw(
        passphrase.encode("utf-8"), salt, time_cost=4, memory_cost=262144,
        parallelism=2, hash_len=32, type=Type.ID, version=19,
    )
    link_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"beebeeb-folder-link-key-v1\x01",
    ).derive(kc + stretch)
    generated = [
        {
            "name": "key_wrap_v1",
            "note": "AES-256-GCM, no AAD; fixed nonce for this public test only.",
            "wrapper_key_hex": wrapper.hex(),
            "inner_key_hex": inner.hex(),
            "nonce_hex": nonce.hex(),
            "wrapped_hex": (nonce + AESGCM(wrapper).encrypt(nonce, inner, None)).hex(),
        },
        {
            "name": "folder_link_passphrase",
            "note": "Argon2id v19, 256 MiB, 4 iterations, 2 lanes, 32 bytes; token-bound SHA-256 salt then folder-link HKDF.",
            "token": token,
            "passphrase": passphrase,
            "k_c_hex": kc.hex(),
            "salt_hex": salt.hex(),
            "stretch_hex": stretch.hex(),
            "link_key_hex": link_key.hex(),
        },
    ]

    nfd = dict(generated[1])
    nfd["name"] = "folder_link_passphrase_nfd"
    nfd["passphrase"] = unicodedata.normalize("NFD", passphrase)
    nfd["note"] = "NFC-normalize before Argon2id; this NFD spelling equals folder_link_passphrase."
    assert unicodedata.normalize("NFC", nfd["passphrase"]) == passphrase
    generated.append(nfd)
    for name, label, record_id, plaintext in [
        ("folder_custody_v1", b"beebeeb-folder-custody-v1", "folder-2237c", inner),
        ("link_owner_key_v1", b"beebeeb-link-owner-key-v1", "share-2237c", kc),
        ("link_owner_token_v1", b"beebeeb-link-owner-token-v1", "share-2237c", token.encode("utf-8")),
    ]:
        context = label + record_id.encode("utf-8")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(wrapper)
        generated.append({
            "name": name, "note": "L6: HKDF info and AES-GCM AAD both equal label || UTF-8 record id; fixed nonce for this public test only.",
            "master_key_hex": wrapper.hex(), "record_id": record_id,
            "label": label.decode("ascii"), "context_hex": context.hex(),
            "purpose_key_hex": key.hex(), "plaintext_hex": plaintext.hex(),
            "nonce_hex": nonce.hex(),
            "wrapped_hex": (nonce + AESGCM(key).encrypt(nonce, plaintext, context)).hex(),
        })
    return generated



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    generated = vectors()
    if args.write:
        path = Path(__file__).resolve().parent.parent / "test-vectors/vectors.json"
        doc = json.loads(path.read_text())
        names = {v["name"] for v in generated}
        doc["vectors"] = [v for v in doc["vectors"] if v["name"] not in names] + generated
        doc["version"] = 10
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps(generated, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
