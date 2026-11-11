//! Core's email normalisation for Swift and Kotlin, so the apps compare emails
//! in the form web and the server use. The safety number a share shows is
//! `share_safety_number`.

use beebeeb_core::contact_keys;

/// An account email in the server's stored form (Rust `str::trim`, then
/// Unicode lower case). Use it for every email that names a contact or a pin.
#[uniffi::export]
pub fn normalize_email(raw: String) -> String {
    contact_keys::normalize_email(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binding_normalizes_with_rust_trim_not_javascript_trim() {
        assert_eq!(normalize_email("\u{0085}A@B.test\u{00A0}".into()), "a@b.test");
        assert_eq!(normalize_email("\u{FEFF}a@b.test".into()), "\u{FEFF}a@b.test");
    }
}
