//! Secrets that cross FFI inside records (core #74 crypto review, P2-5):
//! wiped on drop and `[REDACTED]` in `Debug`. Swift and Kotlin see a plain
//! `String` / `Data` (`ByteArray`) through UniFFI custom types; the bytes
//! UniFFI itself copies across the boundary are outside Rust's reach.

use zeroize::Zeroizing;

/// A secret string field of a record: a password, an authenticator secret or
/// a one-time code.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<SecretString> for String {
    fn from(mut value: SecretString) -> Self {
        std::mem::take(&mut *value.0)
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

uniffi::custom_type!(SecretString, String);

/// A secret byte field of a record, such as passkey PRF output.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<SecretBytes> for Vec<u8> {
    fn from(mut value: SecretBytes) -> Self {
        std::mem::take(&mut *value.0)
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.0.len())
    }
}

uniffi::custom_type!(SecretBytes, Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_fields_never_print_and_survive_the_round_trip() {
        let text = SecretString::from("correct horse battery".to_owned());
        let bytes = SecretBytes::from(vec![0xAB; 32]);
        let printed = format!("{text:?} {bytes:?}");
        assert!(!printed.contains("horse"), "{printed}");
        assert!(!printed.to_ascii_lowercase().contains("ab, ab"), "{printed}");
        assert_eq!(&*text.clone().into_zeroizing(), "correct horse battery");
        assert_eq!(String::from(text), "correct horse battery");
        assert_eq!(Vec::<u8>::from(bytes), vec![0xAB; 32]);
    }
}
