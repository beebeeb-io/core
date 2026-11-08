//! The share safety number for mobile (`beebeeb_core::share_flow::safety`). Thin; public keys only.
use beebeeb_core::share_flow::safety;

use crate::share_flow::ShareFlowFfiError;

#[derive(uniffi::Record)]
pub struct SafetyNumberFfi {
    /// 60 digits, no separators; show as 12 groups of 5.
    pub digits: String,
    /// SHA-256 of the peer's public key: what a local "compared" mark is keyed by.
    pub peer_fingerprint: Vec<u8>,
}

/// The 60-digit number two people compare out of band (Signal's numeric fingerprint, v1).
#[uniffi::export]
pub fn share_safety_number(
    own_user_id: String,
    own_public_key: Vec<u8>,
    peer_user_id: String,
    peer_public_key: Vec<u8>,
) -> Result<SafetyNumberFfi, ShareFlowFfiError> {
    let n = safety::safety_number(&own_user_id, &own_public_key, &peer_user_id, &peer_public_key)?;
    Ok(SafetyNumberFfi {
        digits: n.digits,
        peer_fingerprint: n.peer_fingerprint.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::share_safety_number;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn binding_returns_the_core_vector() {
        let a = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let b = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let n = share_safety_number(
            "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01".into(),
            a,
            "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12".into(),
            b,
        )
        .unwrap();
        assert_eq!(n.digits, "125734655894184515799576627809760712380416734985096630590130");
        assert_eq!(n.peer_fingerprint.len(), 32);
        assert!(share_safety_number("a".into(), vec![0; 31], "b".into(), vec![0; 32]).is_err());
    }
}
