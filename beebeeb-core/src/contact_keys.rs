//! Pure contact-key fingerprints, safety numbers, and pin comparisons.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(crate) const KEY_FINGERPRINT_DOMAIN: &[u8] = b"beebeeb/contact-key/fingerprint/v1";
pub(crate) const SAFETY_NUMBER_DOMAIN: &[u8] = b"beebeeb/contact-key/safety-number/v1";

/// The result of comparing a presented contact-key fingerprint with a pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheck {
    /// No fingerprint has been pinned yet.
    New,
    /// The presented fingerprint matches the existing pin.
    Unchanged,
    /// The presented fingerprint differs from the existing pin.
    Changed,
}

/// Fingerprint a public key under the contact-key domain.
pub fn key_fingerprint(public_key: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KEY_FINGERPRINT_DOMAIN);
    hash.update(public_key);
    hash.finalize().into()
}

/// Derive a symmetric safety number for two public keys.
///
/// Ordering is canonical, so both contacts display the same value regardless
/// of which key is local. The returned bytes are display material, not a key.
pub fn safety_number(a: &[u8], b: &[u8]) -> [u8; 32] {
    let a = key_fingerprint(a);
    let b = key_fingerprint(b);
    let (first, second) = if a <= b { (&a, &b) } else { (&b, &a) };
    let mut hash = Sha256::new();
    hash.update(SAFETY_NUMBER_DOMAIN);
    hash.update(first);
    hash.update(second);
    hash.finalize().into()
}

/// Compare a presented fingerprint with an optional remembered pin.
///
/// This function performs no storage. Callers persist a new pin only after
/// applying their own first-use or changed-key policy.
pub fn check_pin(remembered: Option<&[u8; 32]>, presented: &[u8; 32]) -> PinCheck {
    match remembered {
        None => PinCheck::New,
        Some(pin) if bool::from(pin.ct_eq(presented)) => PinCheck::Unchanged,
        Some(_) => PinCheck::Changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_is_symmetric_and_pin_checks_are_pure() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        assert_eq!(safety_number(&alice, &bob), safety_number(&bob, &alice));

        let fingerprint = key_fingerprint(&alice);
        assert_eq!(check_pin(None, &fingerprint), PinCheck::New);
        assert_eq!(check_pin(Some(&fingerprint), &fingerprint), PinCheck::Unchanged);
        assert_eq!(check_pin(Some(&key_fingerprint(&bob)), &fingerprint), PinCheck::Changed);
    }
}
