//! Fixed-label subkeys for products that store data outside the file tree.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CoreError;
use crate::kdf::MasterKey;

pub(crate) const PASS_KEY_INFO: &[u8] = b"beebeeb/product/pass/v1";
pub(crate) const CHAT_KEY_INFO: &[u8] = b"beebeeb/product/chat/v1";

/// A product whose non-file-tree data has its own fixed-label subkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Pass,
    Chat,
}

impl Product {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Pass => PASS_KEY_INFO,
            Self::Chat => CHAT_KEY_INFO,
        }
    }
}

/// Opaque product key. It is wiped on drop and cannot be cloned.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProductKey {
    bytes: [u8; 32],
}

impl ProductKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for ProductKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProductKey([REDACTED])")
    }
}

/// Derive a product-specific subkey from the account master key.
pub fn derive_product_key(master_key: &MasterKey, product: Product) -> Result<ProductKey, CoreError> {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(product.label(), &mut *key)
        .map_err(|_| CoreError::Kdf("product-key derivation failed".into()))?;
    Ok(ProductKey { bytes: *key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MasterKey;

    #[test]
    fn product_subkeys_are_fixed_and_separated() {
        let master = MasterKey::from_bytes([7u8; 32]);
        let pass = derive_product_key(&master, Product::Pass).unwrap();
        let chat = derive_product_key(&master, Product::Chat).unwrap();
        assert_ne!(pass.as_bytes(), chat.as_bytes());
        assert_eq!(
            pass.as_bytes(),
            derive_product_key(&master, Product::Pass).unwrap().as_bytes()
        );
    }

    /// Known answers computed outside Rust (crypto review, P3), with
    /// Python's `hmac`/`hashlib` as RFC 5869 HKDF-SHA256, no salt:
    /// `hkdf(ikm=bytes([7])*32, info=b"beebeeb/product/pass/v1", L=32)`, and
    /// the same for `chat`. A changed label or derivation fails here.
    #[test]
    fn product_subkeys_match_the_known_answers() {
        let master = MasterKey::from_bytes([7u8; 32]);
        let hex = |key: ProductKey| key.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(derive_product_key(&master, Product::Pass).unwrap()),
            "c92036abc16bf2d550a6a140f8c2b5c2eacb0fe7b5f686c3adc75f17f1cd8cc8"
        );
        assert_eq!(
            hex(derive_product_key(&master, Product::Chat).unwrap()),
            "982ab04e45602d584d3e9b958286d25993d84e965f123f866a9582e349ad7cad"
        );
    }
}
