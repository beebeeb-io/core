use super::*;

#[test]
fn a_folder_key_that_is_not_32_bytes_is_invalid_input() {
    for len in [31usize, 33] {
        assert!(
            matches!(folder_key_id(vec![0x80; len]), Err(CryptoError::InvalidInput { .. })),
            "{len} bytes"
        );
    }
}

#[test]
fn the_32_byte_vector_matches() {
    let key: Vec<u8> = (0x80u8..=0x9f).collect();
    let id = folder_key_id(key).expect("a 32-byte key");
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "e07f022dd6a140210b19530af0a6b316ec4f06b3a2b086fdf0c03c761baf3b07");
}
