use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: ciphertext is invalid or key is wrong")]
    Decryption,

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("OPAQUE protocol error: {0}")]
    Opaque(String),

    #[error("operation cancelled")]
    Cancelled,

    #[error("I/O error: {0}")]
    Io(String),
}
