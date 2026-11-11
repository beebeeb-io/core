//! Account emails in one form, so every client compares them as the server stores them.

/// An account email in the server's stored form: trim, then Unicode lower case.
///
/// No IDNA and no provider rewriting, so two addresses the server keeps apart
/// as two accounts stay apart here too.
///
/// **The trim is Rust's `str::trim`, pinned:** it strips the Unicode
/// `White_Space` characters (U+0009-U+000D, U+0020, U+0085, U+00A0, U+1680,
/// U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, U+3000) and nothing else, as
/// the server's `canonical_email` does. JavaScript's `String.prototype.trim`
/// differs (it strips U+FEFF and keeps U+0085), so a web client calls this
/// function through WASM (`normalizeEmail`) and never trims an email itself.
/// The test below holds a case for each side of the difference.
pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::normalize_email;

    #[test]
    fn normalize_email_is_rust_trim_then_unicode_lower_case() {
        assert_eq!(normalize_email("  Alice@Example.TEST\t"), "alice@example.test");
        // Unicode lower case, no IDNA: U+0130 becomes `i` and U+0307.
        assert_eq!(normalize_email("İNFO@bücher.test"), "i\u{0307}nfo@bücher.test");
        // Unicode White_Space goes, U+0085 included (JavaScript's trim keeps it) ...
        assert_eq!(normalize_email("\u{0085}A@B.test\u{00A0}"), "a@b.test");
        assert_eq!(normalize_email("\u{3000}bob@example.test\u{2028}"), "bob@example.test");
        // ... and U+FEFF stays (JavaScript's trim strips it).
        assert_eq!(normalize_email("\u{FEFF}a@b.test"), "\u{FEFF}a@b.test");
    }
}
