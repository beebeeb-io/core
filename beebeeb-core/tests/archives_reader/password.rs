//! Password-protected zips (spec §7): AES AE-1/AE-2 and ZipCrypto, wrong
//! passwords, mixed archives, the CP437 fallback, and the secret's life.

use beebeeb_core::archives::{ArchivePassword, ArchivePlatform, ArchiveSession, PasswordStep, PieceStep, SessionStep};

use crate::support::{
    Blocking, CP437_TEST_PASSWORD, OTHER_TEST_PASSWORD, TEST_PASSWORD, crc32, drive, first_data_start, fixture,
    fixture_secret, read_entry_with, to_ae1,
};

fn listed(bytes: Vec<u8>) -> ArchiveSession<Blocking> {
    let mut session = ArchiveSession::open(Blocking(bytes), ArchivePlatform::Native);
    assert_eq!(drive(&mut session, |_, r| panic!("{r:?}")), SessionStep::Listed);
    session
}

fn read(session: &mut ArchiveSession<Blocking>, index: u32, password: Option<&str>) -> (Vec<u8>, PieceStep) {
    let password = password.map(|p| ArchivePassword::new(p.to_string()));
    read_entry_with(session, index, password.as_ref(), |_, r| panic!("{r:?}"))
}

fn check(session: &mut ArchiveSession<Blocking>, index: u32, password: &str) -> PasswordStep {
    session.check_password(index, &ArchivePassword::new(password.to_string()))
}

fn index_of(session: &ArchiveSession<Blocking>, name: &str) -> u32 {
    session
        .listing()
        .unwrap()
        .entries
        .iter()
        .find(|e| e.display_path == name)
        .expect(name)
        .index
}

#[test]
fn aes_ae1_and_ae2_all_strengths_verify() {
    let secret = fixture_secret();
    let mut rows = 0;
    for bits in [128u16, 192, 256] {
        let ae2 = fixture(&format!("aes{bits}.zip"));
        for (ae, bytes) in [(2u8, ae2.clone()), (1u8, to_ae1(ae2, crc32(&secret)))] {
            let mut session = listed(bytes);
            let entry = &session.listing().unwrap().entries[0];
            assert_eq!(
                entry.cipher,
                beebeeb_core::archives::EntryCipher::Aes { bits, ae },
                "AES-{bits} AE-{ae}"
            );
            assert_eq!(
                check(&mut session, 0, TEST_PASSWORD),
                PasswordStep::Accepted,
                "AES-{bits} AE-{ae}"
            );
            assert_eq!(
                read(&mut session, 0, Some(TEST_PASSWORD)),
                (secret.clone(), PieceStep::Verified),
                "AES-{bits} AE-{ae}"
            );
            rows += 1;
        }
    }
    assert_eq!(rows, 6);
}

#[test]
fn zipcrypto_right_password_verifies() {
    let mut session = listed(fixture("zipcrypto.zip"));
    assert_eq!(
        session.listing().unwrap().entries[0].cipher,
        beebeeb_core::archives::EntryCipher::ZipCrypto
    );
    assert!(session.listing().unwrap().uses_zipcrypto);
    assert_eq!(check(&mut session, 0, TEST_PASSWORD), PasswordStep::Accepted);
    assert_eq!(
        read(&mut session, 0, Some(TEST_PASSWORD)),
        (fixture_secret(), PieceStep::Verified)
    );
}

#[test]
fn aes_wrong_password_answers_wrong_at_once() {
    let mut session = listed(fixture("aes256.zip"));
    assert_eq!(check(&mut session, 0, "not-the-password"), PasswordStep::Wrong);
    assert_eq!(
        read(&mut session, 0, Some("not-the-password")),
        (Vec::new(), PieceStep::WrongPassword)
    );
    // No password at all is answered the same way, before any byte.
    assert_eq!(read(&mut session, 0, None), (Vec::new(), PieceStep::WrongPassword));
}

#[test]
fn zipcrypto_wrong_password_answers_wrong_at_once() {
    let mut session = listed(fixture("zipcrypto.zip"));
    // Of the first 16 candidates, the check byte refuses 255 in 256; count
    // how many it refused and that each refusal yielded no byte.
    let mut refused = 0;
    for i in 0..16 {
        let candidate = format!("wrong-{i}");
        if check(&mut session, 0, &candidate) == PasswordStep::Wrong {
            assert_eq!(
                read(&mut session, 0, Some(&candidate)),
                (Vec::new(), PieceStep::WrongPassword)
            );
            refused += 1;
        }
    }
    assert!(
        refused >= 14,
        "only {refused} of 16 wrong passwords were refused at once"
    );
    assert_eq!(read(&mut session, 0, None), (Vec::new(), PieceStep::WrongPassword));
}

#[test]
fn wrong_password_passing_quick_check_is_corrupt_not_published() {
    let mut session = listed(fixture("zipcrypto.zip"));
    // A wrong password that passes the 1-in-256 check byte: found by a
    // fixed search, so the same candidate is found every run.
    let candidate = (0..10_000)
        .map(|i| format!("candidate-{i}"))
        .find(|c| check(&mut session, 0, c) == PasswordStep::Accepted)
        .expect("one in 256 candidates passes the check byte");
    let (_, end) = read(&mut session, 0, Some(&candidate));
    assert_ne!(end, PieceStep::Verified, "{candidate} must never verify");
    assert!(
        matches!(end, PieceStep::Corrupt | PieceStep::Skipped(_)),
        "{candidate}: {end:?}"
    );
}

#[test]
fn aes_hmac_tamper_is_corrupt() {
    // Stored and AE-2 (no CRC): one flipped ciphertext byte flips one
    // plaintext byte, and only the authentication code can catch it.
    let mut bytes = fixture("aes256-stored.zip");
    let at = first_data_start(&bytes) + 16 + 2 + 3; // salt, verifier, then data
    bytes[at] ^= 0x01;
    let mut session = listed(bytes);
    assert_eq!(check(&mut session, 0, TEST_PASSWORD), PasswordStep::Accepted);
    let (out, end) = read(&mut session, 0, Some(TEST_PASSWORD));
    assert_eq!(end, PieceStep::Corrupt);
    // The bytes were handed out unverified, and differ in exactly one.
    let secret = fixture_secret();
    assert_eq!(out.iter().zip(&secret).filter(|(a, b)| a != b).count(), 1);
}

#[test]
fn mixed_archive_plain_entries_never_ask() {
    let mut session = listed(fixture("mixed.zip"));
    let (plain, secret) = (index_of(&session, "plain.txt"), index_of(&session, "secret.txt"));
    assert_eq!(
        session.listing().unwrap().protection,
        beebeeb_core::archives::Protection::Some
    );
    assert_eq!(check(&mut session, plain, TEST_PASSWORD), PasswordStep::NotNeeded);
    assert_eq!(
        read(&mut session, plain, None),
        (b"Not protected.\n".to_vec(), PieceStep::Verified)
    );
    assert_eq!(
        read(&mut session, secret, Some(TEST_PASSWORD)),
        (fixture_secret(), PieceStep::Verified)
    );
}

#[test]
fn other_password_entry_skipped() {
    let mut session = listed(fixture("two-passwords.zip"));
    let (first, other) = (index_of(&session, "secret.txt"), index_of(&session, "other.txt"));
    assert_eq!(check(&mut session, first, TEST_PASSWORD), PasswordStep::Accepted);
    assert_eq!(check(&mut session, other, TEST_PASSWORD), PasswordStep::Wrong);
    assert_eq!(
        read(&mut session, other, Some(TEST_PASSWORD)).1,
        PieceStep::WrongPassword
    );
    assert_eq!(
        read(&mut session, other, Some(OTHER_TEST_PASSWORD)),
        (fixture_secret(), PieceStep::Verified)
    );
}

#[test]
fn zipcrypto_cp437_password_fallback() {
    let mut session = listed(fixture("zipcrypto-cp437.zip"));
    assert_eq!(check(&mut session, 0, CP437_TEST_PASSWORD), PasswordStep::Accepted);
    assert_eq!(
        read(&mut session, 0, Some(CP437_TEST_PASSWORD)),
        (fixture_secret(), PieceStep::Verified)
    );
}

#[test]
fn password_never_in_debug_or_errors() {
    let secret = "s3cret-never-printed";
    let password = ArchivePassword::new(secret.to_string());
    assert_eq!(format!("{password:?}"), "ArchivePassword(..)");
    let mut printed = vec![format!("{password:?}"), format!("{password:#?}")];
    for name in ["aes256.zip", "zipcrypto.zip", "mixed.zip"] {
        let mut session = listed(fixture(name));
        printed.push(format!("{:?}", session.listing()));
        printed.push(format!("{:?}", session.check_password(0, &password)));
        let mut reader = session.entry_reader(0, Some(&password)).unwrap();
        for _ in 0..1000 {
            let step = reader.next_piece();
            printed.push(format!("{step:?}"));
            if !matches!(step, PieceStep::Data(_)) {
                break;
            }
        }
    }
    let hits = printed.iter().filter(|text| text.contains(secret)).count();
    assert_eq!(hits, 0, "the password appeared in {hits} printed values");
    assert!(printed.len() >= 8);
}
