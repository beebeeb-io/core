/// BLAKE3 hex digest of a byte slice. Used for content-integrity verification
/// of encrypted blobs (see spec §5).
pub fn blake3_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_known_hash() {
        // BLAKE3 hash of the empty string — fixed test vector.
        assert_eq!(
            blake3_hash(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn deterministic() {
        assert_eq!(blake3_hash(b"hello"), blake3_hash(b"hello"));
        assert_ne!(blake3_hash(b"hello"), blake3_hash(b"world"));
    }
}
