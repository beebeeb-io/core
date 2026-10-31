//! Every domain label in `beebeeb-core`, with the slot it is used in (task 2275
//! L16, round 3, T4).
//!
//! **The collision rule.** HKDF-Expand(PRK, info) for `info = A || id` and
//! `info = B` (or `B || id'`) under the same PRK give the same key when `A` is a
//! prefix of `B` and the caller picks `id = B[len(A)..]`. So a label whose `info`
//! carries concatenated caller bytes must not be a prefix of another HKDF `info`
//! label, and no two labels may be equal. A label in another slot (AES-GCM
//! associated data, an HKDF or Argon2id salt, a SHA-256 domain prefix) never
//! meets an HKDF `info` in the same input of the same primitive, so a prefix
//! relation across slots is not a confusion; each such pair is listed in
//! [`CROSS_SLOT_PREFIX_PAIRS`] with its reason, and the list must match the
//! table exactly.
//!
//! **Completeness.** `the_table_lists_every_label_literal_in_the_crate` reads
//! every `.rs` file under `src/` and requires each `b"beebeeb` byte-string
//! literal followed by `-`, `/` or `.` to be in [`LABELS`] (or in
//! [`NOT_LABELS`]), and each table label to appear as such a literal. A new
//! label cannot be added without joining this table.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{chunk_stream, cli_auth, client_meta, encrypt, file_request, folder_key, item_id, kdf, recovery, transfer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    /// HKDF-SHA256 `info` = label || caller-supplied bytes (an id, a bucket, a
    /// flag). The L6/L8/L16 purpose labels also use the same bytes as AAD.
    InfoWithId,
    /// HKDF-SHA256 `info` = exactly the label.
    Info,
    /// AES-256-GCM associated data = label || fields, under a key derived
    /// elsewhere (never an HKDF `info`).
    Aad,
    /// An HKDF or Argon2id salt, or a SHA-256 domain prefix (never an HKDF `info`).
    Salt,
}

struct Label {
    name: &'static str,
    bytes: &'static [u8],
    slot: Slot,
    /// The key material the label is used with (documentation only: the rule
    /// above holds for every pair, whatever its key).
    with: &'static str,
}

const fn label(name: &'static str, bytes: &'static [u8], slot: Slot, with: &'static str) -> Label {
    Label {
        name,
        bytes,
        slot,
        with,
    }
}

/// Every label in the crate. The three `opaque` labels and the constellation
/// domain are inline literals at their one use; the completeness scan pins them.
const LABELS: &[Label] = &[
    // kdf
    label(
        "kdf::FILE_KEY_INFO",
        kdf::FILE_KEY_INFO,
        Slot::InfoWithId,
        "master key; || file id",
    ),
    label(
        "kdf::SEARCH_INDEX_SHARD_INFO",
        kdf::SEARCH_INDEX_SHARD_INFO,
        Slot::InfoWithId,
        "master key; || bucket u32 LE",
    ),
    label(
        "kdf::SHARED_FOLDER_INDEX_KEY_INFO",
        kdf::SHARED_FOLDER_INDEX_KEY_INFO,
        Slot::InfoWithId,
        "folder key; || bucket u32 LE",
    ),
    label(
        "kdf::FOLDER_LINK_KEY_INFO",
        kdf::FOLDER_LINK_KEY_INFO,
        Slot::InfoWithId,
        "link combiner IKM; || presence byte",
    ),
    label(
        "kdf::FOLDER_LINK_PASSPHRASE_SALT_LABEL",
        kdf::FOLDER_LINK_PASSPHRASE_SALT_LABEL,
        Slot::Salt,
        "SHA-256(token || label) -> Argon2id salt",
    ),
    label(
        "kdf::FOLDER_CHILD_LABEL",
        kdf::FOLDER_CHILD_LABEL,
        Slot::Aad,
        "AAD under the raw folder key (no HKDF)",
    ),
    label(
        "kdf::OWNER_FILE_KEY_LABEL",
        kdf::OWNER_FILE_KEY_LABEL,
        Slot::InfoWithId,
        "master key; || F item id; also the AAD",
    ),
    label(
        "kdf::FOLDER_CUSTODY_LABEL",
        kdf::FOLDER_CUSTODY_LABEL,
        Slot::InfoWithId,
        "master key; || folder id; also the AAD",
    ),
    label(
        "kdf::LINK_OWNER_KEY_LABEL",
        kdf::LINK_OWNER_KEY_LABEL,
        Slot::InfoWithId,
        "master key; || share id; also the AAD",
    ),
    label(
        "kdf::LINK_OWNER_TOKEN_LABEL",
        kdf::LINK_OWNER_TOKEN_LABEL,
        Slot::InfoWithId,
        "master key; || share id; also the AAD",
    ),
    label(
        "kdf::INVITE_OWNER_COPY_LABEL",
        kdf::INVITE_OWNER_COPY_LABEL,
        Slot::InfoWithId,
        "master key; || folder id; also the AAD",
    ),
    label(
        "kdf::LINK_LABEL_LABEL",
        kdf::LINK_LABEL_LABEL,
        Slot::InfoWithId,
        "master key; || 16-byte share id; also the AAD",
    ),
    label(
        "kdf::FOLDER_ACTOR_NAME_INFO",
        kdf::FOLDER_ACTOR_NAME_INFO,
        Slot::InfoWithId,
        "folder key; || 16-byte root id; also the AAD",
    ),
    // folder_key, item_id
    label(
        "folder_key::FOLDER_KEY_ID_INFO",
        folder_key::FOLDER_KEY_ID_INFO,
        Slot::Info,
        "folder key",
    ),
    label(
        "item_id::NEW_ITEM_TAG_INFO",
        item_id::NEW_ITEM_TAG_INFO,
        Slot::Info,
        "master key",
    ),
    // encrypt
    label(
        "encrypt::NAME_KEY_INFO",
        encrypt::NAME_KEY_INFO,
        Slot::Info,
        "per-file key",
    ),
    label(
        "encrypt::THUMBNAIL_KEY_INFO",
        encrypt::THUMBNAIL_KEY_INFO,
        Slot::Info,
        "per-file key",
    ),
    label(
        "encrypt::NOTE_KEY_INFO",
        encrypt::NOTE_KEY_INFO,
        Slot::Info,
        "per-file key",
    ),
    // chunk_stream
    label(
        "chunk_stream::CHUNK_KEY_INFO_V2",
        chunk_stream::CHUNK_KEY_INFO_V2,
        Slot::Info,
        "per-file key",
    ),
    label(
        "chunk_stream::CHUNK_AAD_DOMAIN_V2",
        chunk_stream::CHUNK_AAD_DOMAIN_V2,
        Slot::Aad,
        "AAD under the v2 chunk subkey",
    ),
    // client_meta
    label(
        "client_meta::CLIENT_META_KEY_INFO",
        client_meta::CLIENT_META_KEY_INFO,
        Slot::Info,
        "master key",
    ),
    label(
        "client_meta::AAD_DOMAIN",
        client_meta::AAD_DOMAIN,
        Slot::Aad,
        "AAD under the client-meta key",
    ),
    // file_request
    label(
        "file_request::PRIV_WRAP_INFO",
        file_request::PRIV_WRAP_INFO,
        Slot::InfoWithId,
        "master key; || request id",
    ),
    label(
        "file_request::SEAL_INFO",
        file_request::SEAL_INFO,
        Slot::InfoWithId,
        "X25519 shared secret; || file id",
    ),
    // cli_auth
    label(
        "cli_auth::CLI_AUTH_INFO",
        cli_auth::CLI_AUTH_INFO,
        Slot::Info,
        "P-256 ECDH shared secret",
    ),
    // opaque (inline literals)
    label(
        "opaque x25519 identity info",
        b"beebeeb-x25519-identity",
        Slot::Info,
        "master key",
    ),
    label(
        "opaque recovery check info",
        b"beebeeb-recovery-check",
        Slot::Info,
        "master key",
    ),
    label(
        "opaque share-key salt",
        b"beebeeb-share",
        Slot::Salt,
        "HKDF salt over an X25519 secret; info = file id",
    ),
    // recovery
    label(
        "recovery::RECOVERY_SALT",
        recovery::RECOVERY_SALT,
        Slot::Salt,
        "Argon2id salt over the phrase entropy",
    ),
    // transfer
    label(
        "transfer::crypto::TRANSFER_KEY_INFO",
        transfer::crypto::TRANSFER_KEY_INFO,
        Slot::Info,
        "X25519 secret, salt = session id",
    ),
    label(
        "transfer::crypto::SAS_INFO",
        transfer::crypto::SAS_INFO,
        Slot::Info,
        "X25519 secret, salt = session id",
    ),
    // constellation (inline literal)
    label(
        "constellation confirm-code domain",
        b"beebeeb.constellation.confirm.v1\0",
        Slot::Salt,
        "SHA-256 domain prefix",
    ),
];

/// Every pair where one label is a prefix of another, with why it is not a
/// confusion. `every_prefix_pair_is_documented` requires this list to be exact.
const CROSS_SLOT_PREFIX_PAIRS: &[(&str, &str, &str)] = &[
    (
        "chunk_stream::CHUNK_AAD_DOMAIN_V2",
        "chunk_stream::CHUNK_KEY_INFO_V2",
        "the domain is only AES-GCM associated data under the v2 chunk subkey; the key info is only the HKDF info \
         that derives that subkey from the per-file key (see the_chunk_v2_domain_and_key_info_are_different_key_types)",
    ),
    (
        "client_meta::AAD_DOMAIN",
        "client_meta::CLIENT_META_KEY_INFO",
        "the domain is only AES-GCM associated data under the client-meta key; the key info is only the HKDF info \
         that derives that key from the master key (same split as the chunk pair)",
    ),
    (
        "opaque share-key salt",
        "kdf::SHARED_FOLDER_INDEX_KEY_INFO",
        "`beebeeb-share` is an HKDF salt over an X25519 shared secret (its info is the file id); the index label is an \
         HKDF info over a folder key: different input slots and different IKMs",
    ),
];

/// `b"beebeeb…"` literals under `src/` that are not product labels.
const NOT_LABELS: &[(&[u8], &str)] = &[(
    b"beebeeb-test-salt-16b",
    "src/bin/generate_test_vectors.rs: the fixed Argon2id salt of the test-vector generator",
)];

fn is_hkdf_info(slot: Slot) -> bool {
    matches!(slot, Slot::InfoWithId | Slot::Info)
}

fn find(name: &str) -> &'static Label {
    LABELS
        .iter()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("no label named {name}"))
}

#[test]
fn every_label_is_distinct_and_no_id_carrying_info_is_a_prefix_of_another_info() {
    assert_eq!(LABELS.len(), 32, "a label was added or removed: review the slot rules");
    for (i, a) in LABELS.iter().enumerate() {
        assert!(!a.with.is_empty());
        for b in &LABELS[i + 1..] {
            assert_ne!(a.bytes, b.bytes, "{} and {} are the same label", a.name, b.name);
            for (short, long) in [(a, b), (b, a)] {
                assert!(
                    !(short.slot == Slot::InfoWithId && is_hkdf_info(long.slot) && long.bytes.starts_with(short.bytes)),
                    "{} is a prefix of {}: `{} || id` can equal an HKDF info of {}",
                    short.name,
                    long.name,
                    short.name,
                    long.name
                );
            }
        }
    }
}

#[test]
fn every_prefix_pair_is_documented() {
    let mut found = Vec::new();
    for a in LABELS {
        for b in LABELS {
            if a.name != b.name && b.bytes.starts_with(a.bytes) {
                found.push((a.name, b.name));
            }
        }
    }
    found.sort();
    let mut documented: Vec<(&str, &str)> = CROSS_SLOT_PREFIX_PAIRS.iter().map(|(a, b, _)| (*a, *b)).collect();
    documented.sort();
    assert_eq!(
        found, documented,
        "a prefix pair is new or gone: document it with its reason"
    );
    for (short, long, why) in CROSS_SLOT_PREFIX_PAIRS {
        assert!(!why.is_empty());
        let (short, long) = (find(short), find(long));
        assert!(
            !(short.slot == Slot::InfoWithId && is_hkdf_info(long.slot)),
            "{} -> {} is a real HKDF confusion, not a documented cross-slot pair",
            short.name,
            long.name
        );
    }
}

/// The documented `beebeeb/chunk/v2` / `beebeeb/chunk/v2/key` pair is not a
/// confusion: the shorter string is only ever AES-GCM associated data and the
/// longer only ever the HKDF info of the v2 chunk subkey. They are inputs of
/// different primitives, and the AAD can never be read as the key info.
#[test]
fn the_chunk_v2_domain_and_key_info_are_different_key_types() {
    use chunk_stream::{
        CHUNK_AAD_DOMAIN_V2, CHUNK_KEY_INFO_V2, ChunkFormat, chunk_aad_v2, derive_chunk_key_v2, open_chunk,
    };

    assert!(CHUNK_KEY_INFO_V2.starts_with(CHUNK_AAD_DOMAIN_V2));
    let file_key = kdf::FileKey::from_bytes([0x5a; 32]);
    let file_id = "22750000-0000-4000-8000-000000000001";

    // 1. The subkey is HKDF(file key, the key info). The domain in the info
    //    slot would be a different key, and so is the raw file key.
    let subkey = derive_chunk_key_v2(&file_key);
    assert_eq!(
        subkey.as_bytes(),
        kdf::derive_file_subkey(&file_key, CHUNK_KEY_INFO_V2).as_bytes()
    );
    let domain_as_info = kdf::derive_file_subkey(&file_key, CHUNK_AAD_DOMAIN_V2);
    assert_ne!(subkey.as_bytes(), domain_as_info.as_bytes());
    assert_ne!(subkey.as_bytes(), file_key.as_bytes());

    // 2. Every v2 AAD is the domain then u32_be(len(file id)): byte 16 is the
    //    high byte of a length, never the '/' of "/key".
    let nonce = [0x09; 12];
    let aad = chunk_aad_v2(file_id.as_bytes(), &nonce, 0, true);
    assert!(aad.starts_with(CHUNK_AAD_DOMAIN_V2));
    assert_eq!(aad[16..20], 36u32.to_be_bytes());
    assert!(!aad.starts_with(CHUNK_KEY_INFO_V2));

    // 3. A frame sealed under the subkey with that AAD opens through the real
    //    reader, and under no key or AAD built from the other label's slot.
    let frame = encrypt::seal_raw_with_nonce(&subkey, &nonce, b"chunk", &aad).unwrap();
    assert_eq!(
        open_chunk(&file_key, file_id, &nonce, 0, true, ChunkFormat::V2, &frame).unwrap(),
        b"chunk"
    );
    assert!(encrypt::open_raw_with_aad(&domain_as_info, &frame, &aad).is_err());
    assert!(encrypt::open_raw_with_aad(&file_key, &frame, &aad).is_err());
    assert!(encrypt::open_raw_with_aad(&subkey, &frame, CHUNK_KEY_INFO_V2).is_err());
    assert!(encrypt::open_raw_with_aad(&subkey, &frame, CHUNK_AAD_DOMAIN_V2).is_err());
}

/// The bytes of every `b"beebeeb…"` literal (followed by `-`, `/` or `.`) in `src`.
fn label_literals_in(src: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("b\"beebeeb") {
        let body = &rest[at + 2..];
        let mut bytes = Vec::new();
        let mut chars = body.char_indices();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    end = Some(i);
                    break;
                }
                '\\' => match chars.next().map(|(_, e)| e) {
                    Some('0') => bytes.push(0),
                    Some('\\') => bytes.push(b'\\'),
                    Some('"') => bytes.push(b'"'),
                    Some('n') => bytes.push(b'\n'),
                    other => panic!("unhandled escape {other:?} in a beebeeb byte-string literal"),
                },
                c if c.is_ascii() => bytes.push(c as u8),
                c => panic!("non-ASCII {c:?} in a byte-string literal"),
            }
        }
        let end = end.expect("unterminated byte-string literal");
        if matches!(bytes.get(7), Some(b'-' | b'/' | b'.')) {
            out.push(bytes);
        }
        rest = &body[end + 1..];
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn the_table_lists_every_label_literal_in_the_crate() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let this_file = src.join("label_table_tests.rs");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.retain(|f| *f != this_file);
    assert!(files.len() > 40, "the scan must read the crate (read {})", files.len());

    let mut seen = BTreeSet::new();
    for file in &files {
        for literal in label_literals_in(&std::fs::read_to_string(file).unwrap()) {
            let listed = LABELS.iter().any(|l| l.bytes == literal.as_slice())
                || NOT_LABELS.iter().any(|(b, _)| *b == literal.as_slice());
            assert!(
                listed,
                "{}: {:?} is not in LABELS or NOT_LABELS",
                file.display(),
                String::from_utf8_lossy(&literal)
            );
            seen.insert(literal);
        }
    }
    for l in LABELS {
        assert!(
            seen.contains(l.bytes),
            "{} is listed but is not a literal in src/",
            l.name
        );
    }
    for (bytes, why) in NOT_LABELS {
        assert!(seen.contains(*bytes), "stale NOT_LABELS entry: {why}");
    }
}

#[test]
fn the_literal_scanner_reads_escapes_and_skips_non_labels() {
    let found = label_literals_in(r#"x(b"beebeeb-a-v1"); y(b"beebeeb"); z(b"beebeeb!"); w(b"beebeeb.c.v1\0");"#);
    assert_eq!(found, vec![b"beebeeb-a-v1".to_vec(), b"beebeeb.c.v1\0".to_vec()]);
}
