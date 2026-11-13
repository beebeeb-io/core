//! [`super`] against `test-vectors/screen_lock.json` (written by
//! `test-vectors/tools/make_screen_lock_vectors.py`, an independent implementation), the
//! refusals of an edited or foreign record, and the wrong-try schedule.
//!
//! Every `verify` and `stretch` here is a real canonical Argon2id run (256 MiB): there is no
//! cheaper test cost, so the number of runs is kept small.

use super::*;

const VECTORS_JSON: &str = include_str!("../../test-vectors/screen_lock.json");

struct Row {
    password: Zeroizing<String>,
    owner: String,
    counter: u64,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    token: Zeroizing<[u8; TOKEN_LEN]>,
    stretch: Vec<u8>,
    master_key_stretch: Vec<u8>,
    record: Vec<u8>,
}

fn rows() -> Vec<Row> {
    let document: serde_json::Value = serde_json::from_str(VECTORS_JSON).unwrap();
    assert_eq!(document["format"], "beebeeb/screen-lock/v1");
    assert_eq!(document["argon2id"]["memory_kib"], 256 * 1024);
    assert_eq!(document["argon2id"]["iterations"], 4);
    assert_eq!(document["argon2id"]["lanes"], 2);
    let hex_of = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
    document["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Row {
            password: Zeroizing::new(row["password"].as_str().unwrap().to_owned()),
            owner: row["owner"].as_str().unwrap().to_owned(),
            counter: row["password_counter"].as_u64().unwrap(),
            salt: hex_of(&row["salt"]).try_into().unwrap(),
            nonce: hex_of(&row["nonce"]).try_into().unwrap(),
            token: Zeroizing::new(hex_of(&row["token"]).try_into().unwrap()),
            stretch: hex_of(&row["stretch"]),
            master_key_stretch: hex_of(&row["master_key_stretch"]),
            record: hex_of(&row["record"]),
        })
        .collect()
}

#[test]
fn the_vectors_are_reproduced_byte_for_byte() {
    let rows = rows();
    assert_eq!(rows.len(), 2, "a vector row was added or removed");
    for row in &rows {
        let record = stretch_with_salt(&row.password, row.salt)
            .unwrap()
            .seal_with(&row.owner, row.counter, &row.nonce, &row.token)
            .unwrap();
        assert_eq!(record.to_bytes(), row.record);
        assert_eq!(record.to_bytes().len(), RECORD_LEN);
        assert_eq!(RECORD_LEN, 102);
        assert_eq!(record.password_counter(), Some(row.counter));
    }
}

/// The record of row 0, edited by `edit`, checked with row 0's own password and owner.
fn verify_edited(edit: impl FnOnce(&mut Vec<u8>)) -> CheckOutcome {
    let row = &rows()[0];
    let mut bytes = row.record.clone();
    edit(&mut bytes);
    verify(&ScreenCheckRecord::from_bytes(&bytes), &row.password, &row.owner).unwrap()
}

#[test]
fn the_generators_record_verifies_with_its_password_and_owner() {
    assert_eq!(verify_edited(|_| {}), CheckOutcome::Match);
}

#[test]
fn another_password_does_not_match() {
    let row = &rows()[0];
    let other = Zeroizing::new(format!("{} ", row.password.as_str()));
    let record = ScreenCheckRecord::from_bytes(&row.record);
    assert_eq!(verify(&record, &other, &row.owner).unwrap(), CheckOutcome::NoMatch);
}

#[test]
fn a_record_moved_to_another_owner_never_matches() {
    let row = &rows()[0];
    let record = ScreenCheckRecord::from_bytes(&row.record);
    let foreign = "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12";
    assert_ne!(foreign, row.owner);
    assert_eq!(verify(&record, &row.password, foreign).unwrap(), CheckOutcome::NoMatch);
}

#[test]
fn a_flipped_counter_bit_never_matches() {
    assert_eq!(verify_edited(|bytes| bytes[SALT_AT - 1] ^= 1), CheckOutcome::NoMatch);
}

#[test]
fn a_flipped_tag_bit_never_matches() {
    assert_eq!(
        verify_edited(|bytes| bytes[RECORD_LEN - 1] ^= 0x80),
        CheckOutcome::NoMatch
    );
}

#[test]
fn a_flipped_salt_bit_never_matches() {
    assert_eq!(verify_edited(|bytes| bytes[SALT_AT] ^= 1), CheckOutcome::NoMatch);
}

/// These return before any Argon2id run, so the right password cannot rescue them.
#[test]
fn another_version_pepper_kind_or_length_is_unusable() {
    assert_eq!(verify_edited(|bytes| bytes[0] = 2), CheckOutcome::Unusable);
    assert_eq!(verify_edited(|bytes| bytes[0] = 0), CheckOutcome::Unusable);
    assert_eq!(verify_edited(|bytes| bytes[1] = 1), CheckOutcome::Unusable);
    assert_eq!(verify_edited(|bytes| bytes.push(0)), CheckOutcome::Unusable);
    assert_eq!(
        verify_edited(|bytes| bytes.truncate(RECORD_LEN - 1)),
        CheckOutcome::Unusable
    );
    assert_eq!(verify_edited(Vec::clear), CheckOutcome::Unusable);
    for (edit, readable) in [(0usize, false), (1, false)] {
        let mut bytes = rows()[0].record.clone();
        bytes[edit] ^= 0x10;
        let record = ScreenCheckRecord::from_bytes(&bytes);
        assert_eq!(record.is_readable(), readable);
        assert_eq!(record.password_counter(), None);
    }
}

#[test]
fn no_owner_is_unusable_and_enrolment_refuses_it() {
    let row = &rows()[0];
    let record = ScreenCheckRecord::from_bytes(&row.record);
    assert_eq!(verify(&record, &row.password, "").unwrap(), CheckOutcome::Unusable);
    let long = "o".repeat(MAX_OWNER_LEN + 1);
    assert_eq!(verify(&record, &row.password, &long).unwrap(), CheckOutcome::Unusable);
    assert!(enroll(&row.password, "", 0).is_err());
    assert!(enroll(&row.password, &long, 0).is_err());
    assert!(stretch(&Zeroizing::new(String::new())).is_err());
}

/// Section 3.2, domain separation: the labelled stretch is never the master-key derivation's
/// output for the same password and salt.
#[test]
fn the_stretch_differs_from_the_master_key_derivation() {
    let row = &rows()[0];
    let labelled = stretch_bytes(row.password.as_bytes(), &row.salt).unwrap();
    let master = crate::kdf::derive_master_key(&row.password, &row.salt).unwrap();
    assert_eq!(labelled.as_slice(), row.stretch.as_slice());
    assert_eq!(master.as_bytes().as_slice(), row.master_key_stretch.as_slice());
    assert_ne!(labelled.as_slice(), master.as_bytes().as_slice());
}

#[test]
fn an_enrolled_record_verifies_and_uses_fresh_randomness() {
    let password = Zeroizing::new("a password nobody else has".to_owned());
    let owner = "c41d8a3e-2b7f-4e60-9a15-3d8e7f0b2c44";
    let record = enroll(&password, owner, 7).unwrap();
    assert_eq!(record.password_counter(), Some(7));
    assert_eq!(verify(&record, &password, owner).unwrap(), CheckOutcome::Match);
    let bytes = record.to_bytes();
    assert_ne!(&bytes[SALT_AT..HEADER_LEN], &[0u8; SALT_LEN], "the salt is random");
    assert!(
        !bytes
            .windows(password.len())
            .any(|window| window == password.as_bytes()),
        "the record never contains the password"
    );
    // Two seals under the same key: new nonce and token each time.
    let pending = |key: u8| PendingScreenCheck {
        salt: [9; SALT_LEN],
        check_key: Zeroizing::new([key; 32]),
    };
    let (first, second) = (
        pending(1).seal(owner, 0).unwrap().to_bytes(),
        pending(1).seal(owner, 0).unwrap().to_bytes(),
    );
    assert_ne!(
        first[HEADER_LEN..HEADER_LEN + NONCE_LEN],
        second[HEADER_LEN..HEADER_LEN + NONCE_LEN]
    );
    assert_ne!(first[HEADER_LEN + NONCE_LEN..], second[HEADER_LEN + NONCE_LEN..]);
}

#[test]
fn debug_prints_no_key_and_no_record_bytes() {
    let pending = PendingScreenCheck {
        salt: [0xAB; SALT_LEN],
        check_key: Zeroizing::new([0xCD; 32]),
    };
    let printed = format!("{pending:?}");
    assert_eq!(printed, "PendingScreenCheck([REDACTED])");
    let record = pending.seal("owner", 3).unwrap();
    let printed = format!("{record:?}");
    assert_eq!(printed, "ScreenCheckRecord { bytes: 102 }");
}

#[test]
fn the_wait_follows_the_schedule() {
    const S: u64 = 1_000;
    let table: [(u32, u64); 13] = [
        (0, 0),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 30 * S),
        (6, 60 * S),
        (7, 300 * S),
        (8, 900 * S),
        (9, 3_600 * S),
        (10, 3_600 * S),
        (11, 3_600 * S),
        (u32::MAX, 3_600 * S),
    ];
    let last = 1_000_000;
    for (failures, wait) in table {
        assert_eq!(wait_after_ms(failures), wait, "{failures} failures");
        let state = AttemptState {
            failures,
            last_failure_ms: last,
        };
        let open = if failures >= LOCAL_CHECK_OFF_AT {
            TryDecision::LocalCheckOff
        } else {
            TryDecision::Allowed
        };
        if wait == 0 {
            assert_eq!(next_try(&state, last), open, "{failures} failures, at once");
        } else {
            assert_eq!(next_try(&state, last), TryDecision::WaitUntil(last + wait));
            assert_eq!(next_try(&state, last + wait - 1), TryDecision::WaitUntil(last + wait));
            assert_eq!(next_try(&state, last + wait), open, "{failures} failures, wait over");
        }
    }
    assert_eq!(LOCAL_CHECK_OFF_AT, 10);
}

#[test]
fn each_try_counts_before_it_is_checked() {
    let mut state = AttemptState::new();
    assert_eq!(next_try(&state, 5), TryDecision::Allowed);
    for expected in 1..=4 {
        state = state.counting_try(100 + u64::from(expected));
        assert_eq!(state.failures(), expected);
        assert_eq!(state.last_failure_ms(), 100 + u64::from(expected));
        assert_eq!(next_try(&state, 105), TryDecision::Allowed);
    }
    state = state.counting_try(200);
    assert_eq!(next_try(&state, 200), TryDecision::WaitUntil(30_200));
    let saturated = AttemptState {
        failures: u32::MAX,
        last_failure_ms: 0,
    };
    assert_eq!(saturated.counting_try(1).failures(), u32::MAX);
}

#[test]
fn a_clock_set_back_restarts_the_full_wait() {
    let state = AttemptState {
        failures: 6,
        last_failure_ms: 10_000_000,
    };
    // The clock now reads an hour earlier than the stored failure.
    let now = 10_000_000 - 3_600_000;
    assert_eq!(next_try(&state, now), TryDecision::WaitUntil(now + 60_000));
    let rebased = state.rebased(now);
    assert_eq!((rebased.failures(), rebased.last_failure_ms()), (6, now));
    assert_eq!(next_try(&rebased, now + 59_999), TryDecision::WaitUntil(now + 60_000));
    assert_eq!(next_try(&rebased, now + 60_000), TryDecision::Allowed);
    // A clock that moved forward changes nothing, and neither does an empty state.
    assert_eq!(state.rebased(10_000_001), state);
    assert_eq!(AttemptState::new().rebased(0), AttemptState::new());
}

#[test]
fn the_stored_state_round_trips_and_an_edit_never_buys_tries() {
    let state = AttemptState {
        failures: 7,
        last_failure_ms: 0x0102_0304_0506_0708,
    };
    let bytes = state.to_bytes();
    assert_eq!(bytes.len(), 13);
    assert_eq!(AttemptState::from_bytes(&bytes), Some(state));
    assert_eq!(AttemptState::from_bytes(&bytes[..12]), None);
    assert_eq!(AttemptState::from_bytes(&[]), None);
    let mut other_version = bytes;
    other_version[0] = 2;
    assert_eq!(AttemptState::from_bytes(&other_version), None);
    let assumed = AttemptState::unreadable(500);
    assert_eq!(next_try(&assumed, 500), TryDecision::WaitUntil(500 + 3_600_000));
    assert_eq!(next_try(&assumed, 500 + 3_600_000), TryDecision::LocalCheckOff);
}
