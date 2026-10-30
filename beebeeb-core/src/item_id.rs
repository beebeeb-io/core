//! Item id classes (task 2275, L12).
//!
//! Every server item id is a UUID in canonical lowercase hyphenated text. Two
//! classes exist:
//!
//! * **Foreign** (`F`): RFC 9562 UUID version 8 with the RFC 4122 variant. Core
//!   mints these; the 122 remaining bits are CSPRNG. There is no secret in the
//!   id — it only has to be unguessable enough that another party cannot
//!   pre-create the row.
//! * **Owner** (`O`): every other canonical UUID. For an owner item the key is
//!   derived from the master key and the id, so the id is the only handle.
//!
//! Only the canonical lowercase hyphenated text form is accepted anywhere in
//! core; uppercase, braced, urn and non-hyphenated forms are refused with
//! [`CoreError::InvalidInput`].
//!
//! [`NewItemId`] is the minting type for new rows: it has a private field and
//! can only be built by core through [`NewItemId::owner`] or
//! [`NewItemId::foreign`], so a client cannot seal a new item under an
//! arbitrary (or a pre-existing) id.

use rand::RngCore;
use rand::rngs::OsRng;

use crate::CoreError;

/// The class of an item id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemClass {
    /// Owner item: key material is derived from the master key.
    Owner,
    /// Foreign item: key material comes from an L8 owner-file-key envelope or
    /// an L7 child wrap. Never derived.
    Foreign,
}

/// Mint a new foreign (`F`) item id.
///
/// 16 CSPRNG bytes; byte 6 high nibble is forced to `0x8` (version 8) and byte
/// 8 top two bits to `0b10` (RFC 4122 variant). Returned in canonical
/// lowercase hyphenated form.
pub fn new_foreign_item_id() -> Result<String, CoreError> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

/// Mint a new owner (`O`) id: a random version 4 UUID (canonical lowercase
/// hyphenated). The id carries no secret; the owner key is derived from it.
pub(crate) fn new_owner_item_id() -> Result<String, CoreError> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

/// Parse an id, requiring the exact canonical lowercase hyphenated text form.
pub(crate) fn parse_canonical(id: &str) -> Result<[u8; 16], CoreError> {
    if id.len() != 36
        || id.as_bytes().iter().enumerate().any(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b != b'-',
            _ => !b.is_ascii_digit() && !(b'a'..=b'f').contains(b),
        })
    {
        return Err(CoreError::InvalidInput(format!(
            "item id is not a canonical lowercase hyphenated UUID: {id}"
        )));
    }
    let parsed =
        uuid::Uuid::parse_str(id).map_err(|_| CoreError::InvalidInput(format!("item id is not a UUID: {id}")))?;
    if parsed.to_string() != id {
        return Err(CoreError::InvalidInput(format!(
            "item id is not a canonical lowercase hyphenated UUID: {id}"
        )));
    }
    Ok(*parsed.as_bytes())
}

/// True when `id` is a foreign (`F`) item id: canonical text, UUID version 8,
/// RFC 4122 variant.
///
/// Returns [`CoreError::InvalidInput`] when `id` is not canonical text at all,
/// so a caller cannot mistake a malformed id for an owner id.
pub fn is_foreign_item_id(id: &str) -> Result<bool, CoreError> {
    let bytes = parse_canonical(id)?;
    Ok(is_foreign_bytes(&bytes))
}

pub(crate) fn is_foreign_bytes(bytes: &[u8; 16]) -> bool {
    bytes[6] >> 4 == 8 && bytes[8] & 0xc0 == 0x80
}

/// Classify a canonical item id. Non-canonical text is [`CoreError::InvalidInput`].
pub fn item_class(id: &str) -> Result<ItemClass, CoreError> {
    if is_foreign_item_id(id)? {
        Ok(ItemClass::Foreign)
    } else {
        Ok(ItemClass::Owner)
    }
}

/// An id for a **new** item row, minted by core (task 2275, L13).
///
/// The field is private, so a client cannot build one from an id of its
/// choosing. Use [`NewItemId::owner`] for a derived-key row and
/// [`NewItemId::foreign`] for an adopted (L8) row.
///
/// ```compile_fail
/// // The field is private: a caller cannot name an existing id as "new".
/// let id = beebeeb_core::item_id::NewItemId { id: "11111111-1111-4111-8111-111111111111".into() };
/// ```
///
/// Across an FFI boundary the WASM/uniffi layer mints with
/// [`NewItemId::owner`]/[`NewItemId::foreign`] and hands the id text back to
/// the client; [`NewItemId::from_minted_text`] then re-wraps that text for the
/// sealing call, refusing any id of the wrong class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewItemId {
    id: String,
}

impl NewItemId {
    /// Mint a new owner (`O`) id (random version 4 UUID).
    pub fn owner() -> Result<Self, CoreError> {
        Ok(Self {
            id: new_owner_item_id()?,
        })
    }

    /// Mint a new foreign (`F`) id (random version 8 UUID).
    pub fn foreign() -> Result<Self, CoreError> {
        Ok(Self {
            id: new_foreign_item_id()?,
        })
    }

    /// Re-wrap a minted id text that crossed an FFI boundary (WASM/uniffi).
    ///
    /// The class is re-derived from the id, so an owner id can never be
    /// presented as a foreign new item or vice versa. This does not hand back
    /// any authority: a client could mint an equivalent random id itself, and
    /// writes to an existing row still require a `WriteTarget`.
    pub fn from_minted_text(id: &str) -> Result<Self, CoreError> {
        parse_canonical(id)?;
        Ok(Self { id: id.to_string() })
    }

    /// The canonical lowercase hyphenated id text.
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_ids_are_canonical_v8() {
        for _ in 0..64 {
            let id = new_foreign_item_id().unwrap();
            assert_eq!(id.len(), 36);
            assert_eq!(&id[8..9], "-");
            assert!(is_foreign_item_id(&id).unwrap());
            assert_eq!(item_class(&id).unwrap(), ItemClass::Foreign);
        }
    }

    #[test]
    fn owner_ids_are_canonical_v4() {
        for _ in 0..64 {
            let id = new_owner_item_id().unwrap();
            assert_eq!(id.as_bytes()[14], b'4');
            assert!(!is_foreign_item_id(&id).unwrap());
            assert_eq!(item_class(&id).unwrap(), ItemClass::Owner);
        }
    }

    #[test]
    fn non_canonical_forms_are_refused() {
        for bad in [
            "",
            "not-a-uuid",
            "11111111-1111-8111-8111-11111111111",
            "11111111-1111-8111-8111-1111111111111",
            "1111111-11111-8111-8111-111111111111",
            "11111111_1111_8111_8111_111111111111",
            "11111111111181118111111111111111",
        ] {
            assert!(matches!(is_foreign_item_id(bad), Err(CoreError::InvalidInput(_))));
            assert!(matches!(item_class(bad), Err(CoreError::InvalidInput(_))));
        }
    }
}
