use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    V1Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    Argon2id13,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id13,
            memory_kib: 256 * 1024, // 256 MiB
            iterations: 4,
            parallelism: 2,
        }
    }
}

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
pub const RECOVERY_WORD_COUNT: usize = 12;
