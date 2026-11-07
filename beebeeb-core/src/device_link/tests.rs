use super::*;
use crate::kdf::MasterKey;

const NAME: &str = "Guus's laptop";

fn material(byte: u8) -> AccountKeyMaterial {
    AccountKeyMaterial::from_master_key(MasterKey::from_bytes([byte; 32]))
}

fn other_code(code: &str) -> String {
    let mut bytes = code.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'2' { b'3' } else { b'2' };
    String::from_utf8(bytes).unwrap()
}

/// One full typed-code exchange up to the approver's confirmation.
fn exchange(
    approver_code: Option<&str>,
    approver_session: Option<[u8; 16]>,
    approver_name: &str,
) -> (Result<ConfirmedTypedApproval, CoreError>, TypedCodeReceiver) {
    let session = [3u8; 16];
    let new_device = NewDeviceLink::generate(session, NAME).unwrap();
    let code = approver_code.map_or_else(|| new_device.typed_code().to_owned(), str::to_owned);
    let (approver, approver_message) =
        TypedCodeApprover::start(&code, &approver_session.unwrap_or(session), approver_name).unwrap();
    let (receiver, new_device_message) = new_device.answer_typed_code(&approver_message).unwrap();
    (approver.confirm(&new_device_message), receiver)
}

#[test]
fn qr_payload_round_trips_and_parse_is_strict() {
    let new_device = NewDeviceLink::generate([4u8; 16], NAME).unwrap();
    let payload = new_device.qr_payload();
    assert!(payload.starts_with(QR_PAYLOAD_PREFIX));
    assert_eq!(DeviceLinkQr::parse(&payload).unwrap(), new_device.qr());
    assert_eq!(DeviceLinkQr::parse(&format!(" {payload}\n")).unwrap(), new_device.qr());
    let body = &payload[QR_PAYLOAD_PREFIX.len()..];
    for refused in [
        String::new(),
        body.to_owned(),
        format!("beebeeb-link:v2:{body}"),
        format!("{QR_PAYLOAD_PREFIX}{}", &body[1..]),
        format!("{QR_PAYLOAD_PREFIX}{body}A"),
        format!("{QR_PAYLOAD_PREFIX}{body}=="),
        format!("{QR_PAYLOAD_PREFIX}{} {}", &body[..10], &body[10..]),
        format!("{QR_PAYLOAD_PREFIX}{}", "A".repeat(4096)),
    ] {
        assert!(DeviceLinkQr::parse(&refused).is_err(), "{refused:?} was accepted");
    }
}

#[test]
fn qr_path_seals_to_the_scanned_key_only() {
    let new_device = NewDeviceLink::generate([4u8; 16], NAME).unwrap();
    let qr = DeviceLinkQr::parse(&new_device.qr_payload()).unwrap();
    assert!(qr.verify_public_key(new_device.public_key()));
    assert!(!qr.verify_public_key(&[9u8; 32]));
    let alternate = new_device.typed_code().to_ascii_lowercase().replace('-', " ");
    let sealed = seal_for_new_device(&qr, new_device.public_key(), &alternate, material(8)).unwrap();
    let opened = new_device.open(sealed).unwrap().into_master_key();
    assert_eq!(opened.as_bytes(), &[8u8; 32]);
    assert!(seal_for_new_device(&qr, &[9u8; 32], "K7QM-4WTD", material(8)).is_err());
}

#[test]
fn qr_seal_rejects_wrong_code_like_a_forged_blob() {
    let new_device = NewDeviceLink::generate([4u8; 16], NAME).unwrap();
    let qr = new_device.qr();
    let wrong_code = other_code(new_device.typed_code());
    let sealed = seal_for_new_device(&qr, new_device.public_key(), &wrong_code, material(8)).unwrap();
    assert!(matches!(new_device.open(sealed), Err(CoreError::Decryption)));
}

#[test]
fn qr_seal_rejects_forgery_with_the_same_error() {
    let new_device = NewDeviceLink::generate([4u8; 16], NAME).unwrap();
    let qr = new_device.qr();
    let code = new_device.typed_code().to_owned();
    let sealed = seal_for_new_device(&qr, new_device.public_key(), &code, material(8)).unwrap();
    let mut ciphertext = sealed.ciphertext().to_vec();
    ciphertext[0] ^= 1;
    let forged = SealedAccountKeyMaterial::from_parts(
        *sealed.session_id(),
        *sealed.recipient_public(),
        *sealed.approver_public(),
        *sealed.nonce(),
        ciphertext,
    )
    .unwrap();
    assert!(matches!(new_device.open(forged), Err(CoreError::Decryption)));
}

#[test]
fn low_order_recipient_is_rejected() {
    let qr = DeviceLinkQr {
        session_id: [4u8; 16],
        fingerprint: fingerprint(&[0u8; 32]),
    };
    assert!(seal_for_new_device(&qr, &[0u8; 32], "K7QM-4WTD", material(8)).is_err());
}

#[test]
fn typed_code_exchange_confirms_both_ways_and_opens() {
    let (confirmed, receiver) = exchange(None, None, NAME);
    let confirmed = confirmed.unwrap();
    assert_eq!(confirmed.device_name(), NAME);
    let sealed = confirmed.seal(material(6)).unwrap();
    assert_eq!(sealed.ciphertext().len(), PAKE_SEALED_LEN);
    let opened = receiver.open(sealed).unwrap().into_master_key();
    assert_eq!(opened.as_bytes(), &[6u8; 32]);
}

#[test]
fn approver_sees_a_wrong_code_before_sealing() {
    let new_device_code = NewDeviceLink::generate([3u8; 16], NAME).unwrap();
    let wrong = other_code(new_device_code.typed_code());
    let (confirmed, _) = exchange(Some(&wrong), None, NAME);
    assert!(matches!(confirmed, Err(CoreError::Decryption)));
}

#[test]
fn approver_sees_a_rewritten_device_name() {
    let (confirmed, _) = exchange(None, None, "Attacker's phone");
    assert!(matches!(confirmed, Err(CoreError::Decryption)));
}

#[test]
fn approver_refuses_a_relayed_name_that_is_not_canonical() {
    for name in [" Guus's laptop", "Guus\u{202E}s laptop", "Guus\u{200D}laptop", "", "\t"] {
        assert!(
            TypedCodeApprover::start("K7QM-4WTD", &[3u8; 16], name).is_err(),
            "{name:?} was accepted"
        );
    }
}

#[test]
fn an_answer_from_another_session_does_not_confirm() {
    let (confirmed, _) = exchange(None, Some([4u8; 16]), NAME);
    assert!(matches!(confirmed, Err(CoreError::Decryption)));
}

#[test]
fn new_device_refuses_a_payload_without_the_approver_tag() {
    let (confirmed, receiver) = exchange(None, None, NAME);
    let sealed = confirmed.unwrap().seal(material(6)).unwrap();
    let mut ciphertext = sealed.ciphertext().to_vec();
    ciphertext[0] ^= 1;
    let forged = PakeSealedAccountKeyMaterial::from_parts(*sealed.nonce(), ciphertext).unwrap();
    assert!(matches!(receiver.open(forged), Err(CoreError::Decryption)));
}

#[test]
fn new_device_refuses_a_payload_sealed_in_another_exchange() {
    let (first, _) = exchange(None, None, NAME);
    let (_, second_receiver) = exchange(None, None, NAME);
    let sealed = first.unwrap().seal(material(6)).unwrap();
    assert!(matches!(second_receiver.open(sealed), Err(CoreError::Decryption)));
}

#[test]
fn confirmation_tags_are_separate_per_direction() {
    let keys = PakeKeys::derive(&[7u8; 32], &[3u8; 16], &[1u8; 32], &[2u8; 33], &[5u8; 33]).unwrap();
    assert_ne!(*keys.confirm_new_device, *keys.confirm_approver);
    assert_ne!(*keys.confirm_new_device, *keys.seal);
    assert_ne!(
        keys.tag(&keys.confirm_new_device).unwrap(),
        keys.tag(&keys.confirm_approver).unwrap()
    );
}

#[test]
fn malformed_and_small_order_peer_messages_are_refused() {
    let identity = {
        let mut point = [0u8; 32];
        point[0] = 1;
        point
    };
    let (_, honest) = TypedCodeApprover::start("K7QM-4WTD", &[3u8; 16], NAME).unwrap();
    let mut cases: Vec<Vec<u8>> = Vec::new();
    let mut small_order = vec![PAKE_WIRE_VERSION, SPAKE2_SIDE_B];
    small_order.extend_from_slice(&identity);
    cases.push(small_order);
    let mut wrong_version = honest.clone();
    wrong_version[0] = 1;
    cases.push(wrong_version);
    let mut wrong_side = honest.clone();
    wrong_side[1] = SPAKE2_SIDE_A;
    cases.push(wrong_side);
    let mut non_canonical = vec![PAKE_WIRE_VERSION, SPAKE2_SIDE_B];
    non_canonical.extend_from_slice(&[0xffu8; 32]);
    cases.push(non_canonical);
    cases.push(honest[..honest.len() - 1].to_vec());
    for message in cases {
        let new_device = NewDeviceLink::generate([3u8; 16], NAME).unwrap();
        assert!(
            matches!(new_device.answer_typed_code(&message), Err(CoreError::InvalidInput(_))),
            "{message:?} was accepted"
        );
    }

    let new_device = NewDeviceLink::generate([3u8; 16], NAME).unwrap();
    let code = new_device.typed_code().to_owned();
    let (approver, approver_message) = TypedCodeApprover::start(&code, &[3u8; 16], NAME).unwrap();
    let (_, mut answer) = new_device.answer_typed_code(&approver_message).unwrap();
    answer[2..34].copy_from_slice(&identity);
    assert!(matches!(approver.confirm(&answer), Err(CoreError::InvalidInput(_))));
}

#[test]
fn canonical_device_name_is_idempotent_and_bounded() {
    let cases = [
        ("  Guus's laptop\n", "Guus's laptop"),
        ("Guus\u{202E}'s\u{200B} laptop", "Guus's laptop"),
        ("a\u{200D}b\u{200C}c\u{0007}", "abc"),
        ("\u{0085}iPad\u{3000}", "iPad"),
        ("\u{FEFF}Mac", "Mac"),
    ];
    for (raw, expected) in cases {
        assert_eq!(canonical_device_name(raw).unwrap(), expected, "{raw:?}");
    }
    let long = "x".repeat(200);
    assert_eq!(
        canonical_device_name(&long).unwrap().chars().count(),
        MAX_DEVICE_NAME_SCALARS
    );
    let wide = "\u{1F600}".repeat(60);
    let capped = canonical_device_name(&wide).unwrap();
    assert!(capped.len() <= MAX_DEVICE_NAME_BYTES && capped.len() > MAX_DEVICE_NAME_BYTES - 4);
    let cut_at_space = format!("{} y", "x".repeat(MAX_DEVICE_NAME_SCALARS - 1));
    assert_eq!(canonical_device_name(&cut_at_space).unwrap(), "x".repeat(63));
    for raw in [
        "  Guus's laptop\n",
        "Guus\u{202E}'s laptop",
        &long,
        &wide,
        &cut_at_space,
    ] {
        let once = canonical_device_name(raw).unwrap();
        assert_eq!(canonical_device_name(&once).unwrap(), once);
        assert_eq!(once.trim(), once, "the relay's trim must not change it");
    }
    for blank in ["", "   ", "\u{200B}\u{202E}", "\u{200D}"] {
        assert!(canonical_device_name(blank).is_err(), "{blank:?}");
    }
}

#[test]
fn new_device_link_binds_the_canonical_name() {
    let link = NewDeviceLink::generate([1u8; 16], "  Guus's laptop ").unwrap();
    assert_eq!(link.device_name(), NAME);
    assert!(NewDeviceLink::generate([1u8; 16], " \u{200B} ").is_err());
}

#[test]
fn pre_drawn_seed_hands_out_its_seed_once_and_counts_the_rest() {
    let mut seed = PreDrawnSeed {
        seed: Zeroizing::new([7u8; SCALAR_SEED_LEN]),
        requested: 0,
    };
    let mut first = [0u8; SCALAR_SEED_LEN];
    seed.fill_bytes(&mut first);
    assert_eq!(first, [7u8; SCALAR_SEED_LEN]);
    assert_eq!(seed.requested, SCALAR_SEED_LEN);
    let mut more = [1u8; 8];
    seed.fill_bytes(&mut more);
    assert_eq!(more, [0u8; 8]);
    assert_eq!(seed.requested, SCALAR_SEED_LEN + 8);
}

#[test]
fn link_secret_container_wipes_on_every_drop_path() {
    fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<DeviceLinkSecrets>();
}
