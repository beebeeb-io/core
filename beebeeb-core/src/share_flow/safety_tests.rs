//! Fixed vectors for [`super::safety::safety_number`], so web and mobile can match them.
//!
//! How the vectors were computed: once, outside this crate, with Python's `hashlib` (the script is
//! the contract written out: `h = b"\0\0" + key + uid`; 5200 times `h = sha512(h + key)`; the first
//! 30 bytes as 6 big-endian 5-byte chunks, each `% 100000` as 5 digits; the lower user id first).
//! [`reference_digits`] below is a second, independent re-implementation in this module, so a
//! vector is never only checked against the code under test.
//!
//! Keys: the RFC 7748 §6.1 X25519 public keys (Alice, Bob), plus the bytes `00..1f`.
use sha2::{Digest, Sha256, Sha512};

use super::ShareFlowError;
use super::safety::{SAFETY_DIGITS, key_fingerprint, safety_number};

const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_PK: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const UID_A: &str = "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01";
const UID_B: &str = "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12";
const UID_C: &str = "alice@example.com";

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn seq_key() -> Vec<u8> {
    (0u8..32).collect()
}

/// `(own id, own key, peer id, peer key, 60 digits, SHA-256 of the peer key)`.
type Vector = (&'static str, Vec<u8>, &'static str, Vec<u8>, &'static str, &'static str);

fn vectors() -> Vec<Vector> {
    vec![
        (
            UID_A,
            h(ALICE_PK),
            UID_B,
            h(BOB_PK),
            "125734655894184515799576627809760712380416734985096630590130",
            "f35e5616160a30bf3c6e79fa73c576d40205e8fc3ba4e1c6dcf93e6b98e857b4",
        ),
        (
            UID_B,
            h(BOB_PK),
            UID_A,
            h(ALICE_PK),
            "125734655894184515799576627809760712380416734985096630590130",
            "300c9c9603b92a4b39ed3958bf9240114804db4fd373012c0ca47432d63425ae",
        ),
        (
            UID_A,
            h(ALICE_PK),
            UID_B,
            seq_key(),
            "125734655894184515799576627809405793506231550592539802230670",
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
        ),
        (
            UID_C,
            seq_key(),
            UID_A,
            h(ALICE_PK),
            "125734655894184515799576627809234714408491727850860725221133",
            "300c9c9603b92a4b39ed3958bf9240114804db4fd373012c0ca47432d63425ae",
        ),
    ]
}

/// An independent re-implementation: a fresh buffer per round, digits by u128 arithmetic.
fn reference_party(uid: &str, key: &[u8]) -> String {
    let mut state = [&[0u8, 0u8][..], key, uid.as_bytes()].concat();
    let mut round = 0;
    while round < 5200 {
        let mut input = state.clone();
        input.extend_from_slice(key);
        state = Sha512::digest(&input).to_vec();
        round += 1;
    }
    let mut s = String::new();
    for i in 0..6 {
        let mut n: u128 = 0;
        for b in &state[i * 5..i * 5 + 5] {
            n = n * 256 + u128::from(*b);
        }
        let d = n % 100_000;
        s += &format!("{d:0>5}");
    }
    s
}

fn reference_digits(a: &str, ak: &[u8], b: &str, bk: &[u8]) -> String {
    let (pa, pb) = (reference_party(a, ak), reference_party(b, bk));
    if (a.as_bytes(), ak) <= (b.as_bytes(), bk) {
        pa + &pb
    } else {
        pb + &pa
    }
}

#[test]
fn safety_number_matches_the_fixed_vectors() {
    let vs = vectors();
    for (own, own_key, peer, peer_key, digits, fp) in &vs {
        let got = safety_number(own, own_key, peer, peer_key).unwrap();
        assert_eq!(got.digits, *digits, "{own} -> {peer}");
        assert_eq!(hex::encode(got.peer_fingerprint), *fp);
        assert_eq!(got.digits.len(), SAFETY_DIGITS);
        assert!(got.digits.bytes().all(|c| c.is_ascii_digit()));
    }
    assert_eq!(vs.len(), 4);
}

#[test]
fn the_vectors_match_an_independent_computation() {
    for (own, own_key, peer, peer_key, digits, fp) in vectors() {
        assert_eq!(reference_digits(own, &own_key, peer, &peer_key), digits);
        assert_eq!(hex::encode(Sha256::digest(&peer_key)), fp);
    }
}

#[test]
fn both_sides_see_the_same_digits() {
    let (a, b) = (h(ALICE_PK), h(BOB_PK));
    let ab = safety_number(UID_A, &a, UID_B, &b).unwrap();
    let ba = safety_number(UID_B, &b, UID_A, &a).unwrap();
    assert_eq!(ab.digits, ba.digits);
    assert_ne!(ab.peer_fingerprint, ba.peer_fingerprint);
    assert_eq!(ab.groups().len(), 12);
    assert_eq!(ab.groups()[0], "12573");
}

#[test]
fn a_changed_peer_key_changes_the_number_and_the_fingerprint() {
    let a = h(ALICE_PK);
    let before = safety_number(UID_A, &a, UID_B, &h(BOB_PK)).unwrap();
    let after = safety_number(UID_A, &a, UID_B, &seq_key()).unwrap();
    assert_ne!(before.digits, after.digits);
    assert_ne!(before.peer_fingerprint, after.peer_fingerprint);
    assert_eq!(key_fingerprint(&seq_key()).unwrap(), after.peer_fingerprint);
}

#[test]
fn wrong_inputs_are_refused() {
    let a = h(ALICE_PK);
    assert_eq!(
        safety_number(UID_A, &a, UID_B, &a[..31]).unwrap_err(),
        ShareFlowError::InvalidInput("public key length")
    );
    assert_eq!(
        safety_number("", &a, UID_B, &a).unwrap_err(),
        ShareFlowError::InvalidInput("user id")
    );
    assert!(key_fingerprint(&[0u8; 33]).is_err());
}
