//! The share safety number for mobile (`beebeeb_core::share_flow::safety`). Thin; public keys only.
use beebeeb_core::share_flow::safety;

use zeroize::Zeroizing;

use crate::share_flow::ShareFlowFfiError;

#[derive(uniffi::Record)]
pub struct SafetyNumberFfi {
    /// 60 digits, no separators; show as 12 groups of 5.
    pub digits: String,
    /// SHA-256 of the peer's public key: what a local "compared" mark is keyed by.
    pub peer_fingerprint: Vec<u8>,
}

/// The 60-digit number two people compare out of band (Signal's numeric fingerprint, v1). The own
/// sharing key is derived from `master_key` in core (as the other share exports take it);
/// `peer_public_key` is the key the share was sealed to (`recipient_public_key` of the outcome).
#[uniffi::export]
pub fn share_safety_number(
    master_key: Vec<u8>,
    own_user_id: String,
    peer_user_id: String,
    peer_public_key: Vec<u8>,
) -> Result<SafetyNumberFfi, ShareFlowFfiError> {
    let master_key = Zeroizing::new(master_key);
    let master = crate::share_flow::master(&master_key)?;
    let n = safety::safety_number(&master, &own_user_id, &peer_user_id, &peer_public_key)?;
    Ok(SafetyNumberFfi {
        digits: n.digits,
        peer_fingerprint: n.peer_fingerprint.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::share_safety_number;

    #[test]
    fn binding_derives_the_own_key_and_checks_inputs() {
        let master = vec![1u8; 32];
        let peer = beebeeb_core::opaque::derive_x25519_public(&beebeeb_core::opaque::derive_x25519_private(
            &beebeeb_core::kdf::MasterKey::from_bytes([2; 32]),
        ));
        let (a, b) = (
            "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01",
            "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12",
        );
        let n = share_safety_number(master.clone(), a.into(), b.into(), peer.to_vec()).unwrap();
        assert_eq!(n.digits.len(), 60);
        assert_eq!(n.peer_fingerprint.len(), 32);
        assert!(share_safety_number(master.clone(), a.into(), a.into(), peer.to_vec()).is_err());
        assert!(share_safety_number(master.clone(), a.to_uppercase(), b.into(), peer.to_vec()).is_err());
        assert!(share_safety_number(master, a.into(), b.into(), vec![0; 32]).is_err());
        assert!(share_safety_number(vec![1; 31], a.into(), b.into(), peer.to_vec()).is_err());
    }
}
