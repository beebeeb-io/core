//! [`super::safety`] against `test-vectors/safety_number.json`, written by
//! `test-vectors/tools/make_safety_number_vectors.py` (an independent Python implementation of the
//! contract text; `check-safety-number-vectors-generated.sh` fails on a hand edit). Web and mobile
//! read the same file.
use serde_json::Value;

use super::ShareFlowError;
use super::safety::{SAFETY_DIGITS, key_fingerprint, safety_number_for_keys};

const VECTORS_JSON: &str = include_str!("../../../test-vectors/safety_number.json");
const UID_A: &str = "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01";
const UID_B: &str = "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12";

fn doc() -> Value {
    serde_json::from_str(VECTORS_JSON).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(s(v, k)).unwrap()
}

fn rows<'a>(d: &'a Value, k: &str) -> &'a Vec<Value> {
    d[k].as_array().unwrap()
}

#[test]
fn safety_number_matches_the_json_vectors() {
    let d = doc();
    assert_eq!(d["iterations"], 5200);
    let mut n = 0;
    for v in rows(&d, "vectors") {
        let got = safety_number_for_keys(
            s(v, "own_user_id"),
            &h(v, "own_public_key"),
            s(v, "peer_user_id"),
            &h(v, "peer_public_key"),
        )
        .unwrap();
        assert_eq!(got.digits, s(v, "digits"), "{}", s(v, "name"));
        assert_eq!(
            hex::encode(got.peer_fingerprint),
            s(v, "peer_fingerprint"),
            "{}",
            s(v, "name")
        );
        assert_eq!(got.digits.len(), SAFETY_DIGITS);
        assert_eq!(got.groups().len(), 12);
        n += 1;
    }
    assert_eq!(n, 4);
}

/// P3-2: every row is symmetric — the peer computing it the other way round sees the same digits.
#[test]
fn every_vector_is_symmetric() {
    let d = doc();
    let mut n = 0;
    for v in rows(&d, "vectors") {
        let mine = safety_number_for_keys(
            s(v, "own_user_id"),
            &h(v, "own_public_key"),
            s(v, "peer_user_id"),
            &h(v, "peer_public_key"),
        )
        .unwrap();
        let theirs = safety_number_for_keys(
            s(v, "peer_user_id"),
            &h(v, "peer_public_key"),
            s(v, "own_user_id"),
            &h(v, "own_public_key"),
        )
        .unwrap();
        assert_eq!(mine.digits, theirs.digits, "{}", s(v, "name"));
        assert_eq!(
            hex::encode(Sha256(&h(v, "own_public_key"))),
            hex::encode(theirs.peer_fingerprint)
        );
        n += 1;
    }
    assert_eq!(n, 4);
}

#[allow(non_snake_case)]
fn Sha256(b: &[u8]) -> [u8; 32] {
    key_fingerprint(b).unwrap()
}

/// P2-2, P3-1: non-canonical ids, equal ids (the tie-break case), and keys the seal refuses.
#[test]
fn the_json_refusals_are_refused() {
    let d = doc();
    let mut n = 0;
    for v in rows(&d, "refused") {
        let got = safety_number_for_keys(
            s(v, "own_user_id"),
            &h(v, "own_public_key"),
            s(v, "peer_user_id"),
            &h(v, "peer_public_key"),
        );
        match got {
            Err(e) => assert_eq!(e.code(), s(v, "code"), "{}", s(v, "name")),
            Ok(_) => panic!("accepted: {}", s(v, "name")),
        }
        n += 1;
    }
    assert_eq!(n, 8);
}

#[test]
fn equal_ids_are_refused_even_with_different_keys() {
    let d = doc();
    let v = &rows(&d, "vectors")[0];
    assert!(matches!(
        safety_number_for_keys(UID_A, &h(v, "own_public_key"), UID_A, &h(v, "peer_public_key")),
        Err(ShareFlowError::InvalidInput(_))
    ));
    assert!(safety_number_for_keys(UID_A, &h(v, "own_public_key"), UID_B, &h(v, "peer_public_key")).is_ok());
}

#[test]
fn a_changed_peer_key_changes_the_number_and_the_fingerprint() {
    let d = doc();
    let (v0, v2) = (&rows(&d, "vectors")[0], &rows(&d, "vectors")[2]);
    assert_eq!(s(v0, "peer_user_id"), s(v2, "peer_user_id"));
    assert_ne!(s(v0, "digits"), s(v2, "digits"));
    assert_ne!(s(v0, "peer_fingerprint"), s(v2, "peer_fingerprint"));
    assert!(key_fingerprint(&[0u8; 33]).is_err());
}
