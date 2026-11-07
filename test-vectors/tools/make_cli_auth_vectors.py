#!/usr/bin/env python3
"""Independently generate the CLI-auth handshake known answers (task 2378).

Pure Python (affine P-256 arithmetic, HMAC-SHA256 HKDF from the standard library).
No Rust implementation or generated output is run, and no third-party package is
imported, so the answers share no code with the `p256` / `hkdf` crates they check.
The curve math was written by the task-2378 crypto review; only public, fixed test
scalars are used (variable-time arithmetic is fine for them, never for a real key).

    python3 -I test-vectors/tools/make_cli_auth_vectors.py
        prints the constants as Rust `const` lines
    python3 -I test-vectors/tools/make_cli_auth_vectors.py --check beebeeb-core/tests/cli_auth_vectors.rs
        exits 1 unless every constant below appears in the file with exactly this value
    python3 -I test-vectors/tools/make_cli_auth_vectors.py --self-test beebeeb-core/tests/cli_auth_vectors.rs
        exits 0 only if --check rejects an in-memory copy with one nibble flipped

The derivation (beebeeb-core/src/cli_auth.rs): shared = X-coordinate of the P-256
ECDH point; key = HKDF-SHA256(ikm = shared, salt = None, info = "beebeeb-cli-auth-v1").
"""
import hashlib
import hmac
import re
import sys

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

CLI_PRIV = bytes([0x11]) * 32
BROWSER_PRIV = bytes([0x22]) * 32
INFO = b"beebeeb-cli-auth-v1"


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], -1, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return (x, (lam * (p1[0] - x) - p1[1]) % P)


def mul(k, point):
    acc = None
    while k:
        if k & 1:
            acc = add(acc, point)
        point = add(point, point)
        k >>= 1
    return acc


def on_curve(pt):
    return (pt[1] * pt[1] - (pt[0] ** 3 + A * pt[0] + B)) % P == 0


def sec1_uncompressed(pt):
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def sec1_compressed(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def hkdf_sha256_32(ikm, info):
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()  # salt None = HashLen zeros
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()  # T(1) is 32 bytes


def off_curve_x():
    """Smallest x >= 1 with x^3 + ax + b a non-residue mod p: no point has this X."""
    x = 1
    while pow((x ** 3 + A * x + B) % P, (P - 1) // 2, P) != P - 1:
        x += 1
    return x


def vectors():
    cli, browser = int.from_bytes(CLI_PRIV, "big"), int.from_bytes(BROWSER_PRIV, "big")
    assert 0 < cli < N and 0 < browser < N
    cli_pub, browser_pub = mul(cli, G), mul(browser, G)
    assert on_curve(cli_pub) and on_curve(browser_pub)
    s1, s2 = mul(browser, cli_pub), mul(cli, browser_pub)
    assert s1 == s2
    shared = s1[0].to_bytes(32, "big")
    return [
        ("CLI_PRIV_HEX", CLI_PRIV.hex()),
        ("BROWSER_PRIV_HEX", BROWSER_PRIV.hex()),
        ("EXPECTED_AES_KEY_HEX", hkdf_sha256_32(shared, INFO).hex()),
        ("EXPECTED_SHARED_HEX", shared.hex()),
        ("EXPECTED_CLI_PUB_HEX", sec1_uncompressed(cli_pub).hex()),
        ("EXPECTED_BROWSER_PUB_HEX", sec1_uncompressed(browser_pub).hex()),
        ("BROWSER_PUB_COMPRESSED_HEX", sec1_compressed(browser_pub).hex()),
        ("OFF_CURVE_COMPRESSED_HEX", (b"\x02" + off_curve_x().to_bytes(32, "big")).hex()),
    ]


def mismatches(rows, text):
    found = dict(re.findall(r'const ([A-Z0-9_]+): &str = "([0-9a-f]*)";', text))
    return [(n, v, found.get(n)) for n, v in rows if found.get(n) != v]


def main(argv):
    rows = vectors()
    if len(argv) == 1:
        for name, value in rows:
            print(f'const {name}: &str = "{value}";')
        return 0
    if len(argv) == 3 and argv[1] == "--check":
        bad = mismatches(rows, open(argv[2], encoding="utf-8").read())
        for name, want, got in bad:
            print(f"cli-auth vectors: {name}: generator {want}, file {got}", file=sys.stderr)
        print(f"cli-auth vectors: {len(rows) - len(bad)} of {len(rows)} constants match the generator")
        return 1 if bad else 0
    if len(argv) == 3 and argv[1] == "--self-test":
        # The check must REJECT a copy with one nibble of one constant flipped (in memory).
        text = open(argv[2], encoding="utf-8").read()
        name, value = rows[3]  # EXPECTED_SHARED_HEX
        flipped = value[:-1] + ("0" if value[-1] != "0" else "1")
        mutant = text.replace(f'"{value}"', f'"{flipped}"', 1)
        if mutant == text:
            print(f"cli-auth self-test: {name} not found in {argv[2]}", file=sys.stderr)
            return 1
        if [n for n, _, _ in mismatches(rows, mutant)] != [name]:
            print("cli-auth self-test: the check did not reject the mutant", file=sys.stderr)
            return 1
        print(f"cli-auth self-test: the check rejects a one-nibble change to {name}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
