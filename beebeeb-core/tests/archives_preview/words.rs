//! The words (spec §9): one key, one English source, plurals in core.

use beebeeb_core::archives::{ArchiveKey, archive_text};
use std::collections::BTreeSet;

#[test]
fn words_every_key_has_text() {
    // Spec §9 lists 63 keys.
    assert_eq!(ArchiveKey::ALL.len(), 63);
    let mut seen = BTreeSet::new();
    for key in ArchiveKey::ALL {
        assert!(seen.insert(key.key()), "duplicate key {}", key.key());
        let text = archive_text(key, &[]);
        assert_eq!(text.key, key.key());
        assert!(!text.text.is_empty(), "{} has no text", key.key());
    }
    assert_eq!(
        archive_text(ArchiveKey::RefuseSfx, &[]).text,
        "This is a self-extracting program, not a plain archive."
    );
}

#[test]
fn words_plural_one_file() {
    let one = archive_text(
        ArchiveKey::ArchiveSummary,
        &[("files", "1"), ("folders", "1"), ("size", "3 KB")],
    );
    assert_eq!(one.text, "1 file, 1 folder · 3 KB");
    let many = archive_text(
        ArchiveKey::ArchiveSummary,
        &[("files", "2"), ("folders", "0"), ("size", "3 KB")],
    );
    assert_eq!(many.text, "2 files, 0 folders · 3 KB");
    assert_eq!(
        many.args,
        vec![
            ("files".to_string(), "2".to_string()),
            ("folders".to_string(), "0".to_string()),
            ("size".to_string(), "3 KB".to_string())
        ]
    );
    assert_eq!(
        archive_text(ArchiveKey::ActionExtractSelected, &[("n", "1")]).text,
        "Extract 1 item"
    );
    assert_eq!(
        archive_text(ArchiveKey::ExtractRenamed, &[("n", "1")]).text,
        "1 file had the same name as another file and was renamed."
    );
    assert_eq!(
        archive_text(ArchiveKey::ExtractRenamed, &[("n", "3")]).text,
        "3 files had the same name as another file and were renamed."
    );
}

#[test]
fn words_ellipsis_is_u2026() {
    for key in [ArchiveKey::ArchiveReading, ArchiveKey::ActionExtractTo] {
        let text = archive_text(key, &[]).text;
        assert!(text.ends_with('\u{2026}'), "{text}");
        assert!(!text.contains("..."), "{text}");
    }
    assert_eq!(
        archive_text(ArchiveKey::ActionExtractTo, &[]).text,
        "Extract to\u{2026}"
    );
}
