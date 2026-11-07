//! WinZip AES (AE-1 and AE-2), decryption only.
//!
//! The format: a salt (8, 12 or 16 bytes for AES-128, -192, -256) and a
//! 2-byte password verifier precede the data; a 10-byte authentication code
//! follows it. PBKDF2-HMAC-SHA1 (1,000 iterations) turns the password and
//! salt into the AES key, the HMAC key and the verifier. The data is
//! AES-CTR with a little-endian counter starting at 1, and the code is the
//! first 10 bytes of HMAC-SHA1 over the ciphertext. Built on core's own
//! `aes`, `hmac`, `sha1` and `subtle`; every derived key is wiped on drop.

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha1 = Hmac<Sha1>;

pub(crate) const AUTH_CODE_LEN: usize = 10;
const ITERATIONS: u32 = 1000;

/// Salt length for a key size in bits; `None` for any other size.
pub(crate) fn salt_len(bits: u16) -> Option<usize> {
    match bits {
        128 => Some(8),
        192 => Some(12),
        256 => Some(16),
        _ => None,
    }
}

enum Cipher {
    Aes128(aes::Aes128),
    Aes192(aes::Aes192),
    Aes256(aes::Aes256),
}

/// An entry's decryptor after its verifier matched.
pub(crate) struct AesDecryptor {
    cipher: Cipher,
    mac: HmacSha1,
    counter: u128,
    keystream: Zeroizing<[u8; 16]>,
    used: usize,
}

/// Derive the keys for `password` and `salt`; `None` when the verifier
/// does not match (a wrong password, 65,535 times in 65,536).
pub(crate) fn open(password: &[u8], bits: u16, salt: &[u8], verifier: [u8; 2]) -> Option<AesDecryptor> {
    let key_len = usize::from(bits / 8);
    let mut derived = Zeroizing::new(vec![0u8; 2 * key_len + 2]);
    pbkdf2_hmac_sha1(password, salt, ITERATIONS, &mut derived);
    if !bool::from(derived[2 * key_len..].ct_eq(&verifier)) {
        return None;
    }
    let key = &derived[..key_len];
    let cipher = match bits {
        128 => Cipher::Aes128(aes::Aes128::new_from_slice(key).ok()?),
        192 => Cipher::Aes192(aes::Aes192::new_from_slice(key).ok()?),
        256 => Cipher::Aes256(aes::Aes256::new_from_slice(key).ok()?),
        _ => return None,
    };
    let mac = <HmacSha1 as Mac>::new_from_slice(&derived[key_len..2 * key_len]).ok()?;
    Some(AesDecryptor {
        cipher,
        mac,
        counter: 0,
        keystream: Zeroizing::new([0u8; 16]),
        used: 16,
    })
}

impl AesDecryptor {
    /// Authenticate then decrypt the next ciphertext bytes, in place.
    pub(crate) fn decrypt(&mut self, bytes: &mut [u8]) {
        self.mac.update(bytes);
        for b in bytes {
            if self.used == 16 {
                self.counter = self.counter.wrapping_add(1);
                let mut block = GenericArray::clone_from_slice(&self.counter.to_le_bytes());
                match &self.cipher {
                    Cipher::Aes128(c) => c.encrypt_block(&mut block),
                    Cipher::Aes192(c) => c.encrypt_block(&mut block),
                    Cipher::Aes256(c) => c.encrypt_block(&mut block),
                }
                self.keystream.copy_from_slice(&block);
                block.zeroize();
                self.used = 0;
            }
            *b ^= self.keystream[self.used];
            self.used += 1;
        }
    }

    /// Whether the stored code matches the HMAC of every ciphertext byte
    /// seen, in constant time.
    pub(crate) fn verify(self, stored: &[u8]) -> bool {
        let tag = self.mac.finalize().into_bytes();
        stored.len() == AUTH_CODE_LEN && bool::from(tag[..AUTH_CODE_LEN].ct_eq(stored))
    }
}

/// PBKDF2 (RFC 8018) with HMAC-SHA1 as the PRF.
fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let Ok(keyed) = <HmacSha1 as Mac>::new_from_slice(password) else {
        return;
    };
    for (block_index, chunk) in out.chunks_mut(20).enumerate() {
        let mut mac = keyed.clone();
        mac.update(salt);
        mac.update(&(block_index as u32 + 1).to_be_bytes());
        let mut u = Zeroizing::new(<[u8; 20]>::from(mac.finalize().into_bytes()));
        let mut t = Zeroizing::new(*u);
        for _ in 1..iterations {
            let mut mac = keyed.clone();
            mac.update(&u[..]);
            *u = mac.finalize().into_bytes().into();
            for (t, u) in t.iter_mut().zip(u.iter()) {
                *t ^= u;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::pbkdf2_hmac_sha1;

    /// RFC 6070's PBKDF2-HMAC-SHA1 vectors.
    #[test]
    fn pbkdf2_matches_rfc_6070() {
        let rows: [(&[u8], &[u8], u32, &str); 3] = [
            (b"password", b"salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            (b"password", b"salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
        ];
        for (password, salt, iterations, expected) in rows {
            let mut out = vec![0u8; expected.len() / 2];
            pbkdf2_hmac_sha1(password, salt, iterations, &mut out);
            assert_eq!(hex::encode(out), expected, "{iterations} iterations");
        }
    }
}
