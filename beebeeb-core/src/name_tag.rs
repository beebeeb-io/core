//! The normalised form of a file or folder name: two names clash when their
//! normalised forms are equal.
//!
//! `normalize(name) = NFKC(simple_casefold(NFKC(name)))`: NFKC, then simple case
//! folding (CaseFolding.txt statuses C and S, never F or T), then NFKC again, so
//! the result is in NFKC. Simple folding matches the case-insensitive file
//! systems the clients mirror: `ẞ` and `ß` are one name, `ß` and `ss` are not, and
//! `İ` keeps its dot. Nothing is trimmed and no default-ignorable character is
//! removed: a zero-width joiner makes a different name.
//!
//! The NFKC tables (`unicode-normalization`) and the folding table are at one
//! Unicode version ([`unicode_version`]), pinned in `Cargo.lock`.

mod case_fold;

/// The longest name, in UTF-8 bytes, that is normalised. Checked before
/// normalising: NFKC can grow a name many times over.
pub const MAX_INPUT_BYTES: usize = 1024;

/// The longest normalised form, in UTF-8 bytes.
pub const MAX_NORMALIZED_BYTES: usize = 4096;

/// A name that is never normalised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NormalizeError {
    #[error("an empty name has no normalised form")]
    Empty,
    #[error("a name over {MAX_INPUT_BYTES} bytes, or over {MAX_NORMALIZED_BYTES} once normalised, is not normalised")]
    TooLong,
}

/// The Unicode version of the normalisation and folding tables.
pub fn unicode_version() -> &'static str {
    case_fold::UNICODE_VERSION
}

/// `name`'s normalised form (see the module documentation).
pub fn normalize_for_tag(name: &str) -> Result<String, NormalizeError> {
    use unicode_normalization::UnicodeNormalization;

    if name.is_empty() {
        return Err(NormalizeError::Empty);
    }
    if name.len() > MAX_INPUT_BYTES {
        return Err(NormalizeError::TooLong);
    }
    let folded: String = name.nfkc().map(simple_fold).collect();
    let normalized: String = folded.nfkc().collect();
    if normalized.len() > MAX_NORMALIZED_BYTES {
        return Err(NormalizeError::TooLong);
    }
    Ok(normalized)
}

/// `c`'s simple case fold, or `c` when it has none.
fn simple_fold(c: char) -> char {
    case_fold::SIMPLE_FOLDS
        .binary_search_by_key(&u32::from(c), |&(from, _)| from)
        .ok()
        .and_then(|index| char::from_u32(case_fold::SIMPLE_FOLDS[index].1))
        .unwrap_or(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_folding_table_is_sorted_and_at_the_nfkc_tables_version() {
        assert!(case_fold::SIMPLE_FOLDS.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(
            case_fold::SIMPLE_FOLDS
                .iter()
                .all(|&(from, to)| char::from_u32(from).is_some() && char::from_u32(to).is_some())
        );
        let (major, minor, patch) = unicode_normalization::UNICODE_VERSION;
        assert_eq!(unicode_version(), format!("{major}.{minor}.{patch}"));
    }

    /// Every BMP character, alone, between letters and before a combining mark,
    /// normalises to a form that normalises to itself. The combining marks catch
    /// a fold that leaves a pair the second NFKC composes (`T` + U+0308).
    #[test]
    fn normalising_twice_changes_nothing_for_any_bmp_character() {
        for code in 0u32..=0xFFFF {
            let Some(c) = char::from_u32(code) else {
                continue;
            };
            for name in [
                c.to_string(),
                format!("a{c}b"),
                format!("{c}\u{0308}"),
                format!("{c}\u{0313}"),
                format!("{c}\u{0342}"),
            ] {
                if let Ok(once) = normalize_for_tag(&name) {
                    assert_eq!(normalize_for_tag(&once), Ok(once.clone()), "U+{code:04X}");
                }
            }
        }
    }

    #[test]
    fn empty_and_overlong_names_are_refused() {
        assert_eq!(normalize_for_tag(""), Err(NormalizeError::Empty));
        assert_eq!(
            normalize_for_tag(&"a".repeat(MAX_INPUT_BYTES + 1)),
            Err(NormalizeError::TooLong)
        );
        assert!(normalize_for_tag(&"a".repeat(MAX_INPUT_BYTES)).is_ok());
        // U+FDFA grows to 18 characters (33 bytes) under NFKC: 341 of them are
        // 1023 bytes in, 11,253 out.
        assert_eq!(normalize_for_tag(&"\u{FDFA}".repeat(341)), Err(NormalizeError::TooLong));
    }
}
