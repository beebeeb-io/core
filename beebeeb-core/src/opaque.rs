use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::kdf::MasterKey;

pub struct OpaqueEnvelope {
    pub master_key: [u8; 32],
    pub x25519_private: [u8; 32],
    pub recovery_check: [u8; 32],
}

impl Drop for OpaqueEnvelope {
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.x25519_private.zeroize();
        self.recovery_check.zeroize();
    }
}

impl OpaqueEnvelope {
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&self.master_key);
        buf[32..64].copy_from_slice(&self.x25519_private);
        buf[64..96].copy_from_slice(&self.recovery_check);
        buf
    }

    pub fn from_bytes(bytes: &[u8; 96]) -> Self {
        let mut master_key = [0u8; 32];
        let mut x25519_private = [0u8; 32];
        let mut recovery_check = [0u8; 32];
        master_key.copy_from_slice(&bytes[..32]);
        x25519_private.copy_from_slice(&bytes[32..64]);
        recovery_check.copy_from_slice(&bytes[64..96]);
        Self {
            master_key,
            x25519_private,
            recovery_check,
        }
    }

    pub fn into_master_key(self) -> MasterKey {
        MasterKey::from_bytes(self.master_key)
    }
}

pub fn derive_x25519_private(master_key: &MasterKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"beebeeb-x25519-identity", &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    *okm
}

pub fn derive_x25519_public(private_key: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}

pub fn compute_recovery_check(master_key: &MasterKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"beebeeb-recovery-check", &mut okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    okm
}

pub fn x25519_shared_secret(my_private: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*my_private);
    let public = PublicKey::from(*their_public);
    let shared = secret.diffie_hellman(&public);
    *shared.as_bytes()
}

pub fn derive_share_key(shared_secret: &[u8; 32], file_id: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"beebeeb-share"), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(file_id, &mut okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_master_key;

    #[test]
    fn x25519_keypair_from_master_key() {
        let mk = derive_master_key("test-password", b"sixteen-byte-salt").unwrap();
        let private = derive_x25519_private(&mk);
        let public = derive_x25519_public(&private);
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        assert_ne!(private, public);
    }

    #[test]
    fn x25519_keypair_deterministic() {
        let mk = derive_master_key("test-password", b"sixteen-byte-salt").unwrap();
        let priv1 = derive_x25519_private(&mk);
        let priv2 = derive_x25519_private(&mk);
        assert_eq!(priv1, priv2);
    }

    #[test]
    fn x25519_dh_shared_secret() {
        let mk_a = derive_master_key("alice", b"sixteen-byte-salt").unwrap();
        let mk_b = derive_master_key("bob-pw", b"sixteen-byte-salt").unwrap();

        let priv_a = derive_x25519_private(&mk_a);
        let pub_a = derive_x25519_public(&priv_a);
        let priv_b = derive_x25519_private(&mk_b);
        let pub_b = derive_x25519_public(&priv_b);

        let shared_ab = x25519_shared_secret(&priv_a, &pub_b);
        let shared_ba = x25519_shared_secret(&priv_b, &pub_a);
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn share_key_derivation() {
        let mk_a = derive_master_key("alice", b"sixteen-byte-salt").unwrap();
        let mk_b = derive_master_key("bob-pw", b"sixteen-byte-salt").unwrap();

        let priv_a = derive_x25519_private(&mk_a);
        let pub_b = derive_x25519_public(&derive_x25519_private(&mk_b));

        let shared = x25519_shared_secret(&priv_a, &pub_b);
        let share_key = derive_share_key(&shared, b"test-file-uuid");
        assert_eq!(share_key.len(), 32);
    }

    #[test]
    fn share_key_different_per_file() {
        let mk_a = derive_master_key("alice", b"sixteen-byte-salt").unwrap();
        let mk_b = derive_master_key("bob-pw", b"sixteen-byte-salt").unwrap();

        let priv_a = derive_x25519_private(&mk_a);
        let pub_b = derive_x25519_public(&derive_x25519_private(&mk_b));

        let shared = x25519_shared_secret(&priv_a, &pub_b);
        let sk1 = derive_share_key(&shared, b"file-1");
        let sk2 = derive_share_key(&shared, b"file-2");
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn recovery_check_deterministic() {
        let mk = derive_master_key("test-password", b"sixteen-byte-salt").unwrap();
        let rc1 = compute_recovery_check(&mk);
        let rc2 = compute_recovery_check(&mk);
        assert_eq!(rc1, rc2);
    }

    #[test]
    fn envelope_round_trip() {
        let envelope = OpaqueEnvelope {
            master_key: [1u8; 32],
            x25519_private: [2u8; 32],
            recovery_check: [3u8; 32],
        };
        let bytes = envelope.to_bytes();
        let restored = OpaqueEnvelope::from_bytes(&bytes);
        assert_eq!(restored.master_key, [1u8; 32]);
        assert_eq!(restored.x25519_private, [2u8; 32]);
        assert_eq!(restored.recovery_check, [3u8; 32]);
    }
}
