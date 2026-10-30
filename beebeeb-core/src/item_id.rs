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
//! [`NewItemId`] is the minting type for new rows: it has private fields and
//! can only be built by core through [`NewItemId::owner`], [`NewItemId::foreign`]
//! or [`NewItemId::resume`], so a client cannot seal a new item under an
//! arbitrary (or a pre-existing) id. Every mint also returns a *tag*: an
//! HMAC-SHA256 under a master-derived purpose key over the id's canonical text.
//! A client persists the tag with its upload session and passes it back to
//! [`NewItemId::resume`] after a restart; core re-checks it in constant time, so
//! an id the server echoed or invented cannot be resumed. No export computes a
//! tag for an arbitrary id.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::CoreError;
use crate::kdf::MasterKey;

/// HKDF-SHA256 `info` of the new-item-id tag key (ikm = the master key).
pub const NEW_ITEM_TAG_INFO: &[u8] = b"beebeeb/new-item-id/v1";

/// Length of a [`NewItemId`] resume tag in bytes.
pub const NEW_ITEM_TAG_LEN: usize = 32;

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
/// The fields are private, so a client cannot build one from an id of its
/// choosing. Use [`NewItemId::owner`] for a derived-key row and
/// [`NewItemId::foreign`] for an adopted (L8) row. Both take the master key and
/// also mint the [`tag`](Self::tag) that a persisted upload session must carry.
///
/// ```compile_fail
/// // The fields are private: a caller cannot name an existing id as "new".
/// let id = beebeeb_core::item_id::NewItemId { id: "11111111-1111-4111-8111-111111111111".into(), tag: [0; 32] };
/// ```
///
/// Across an FFI boundary the WASM/uniffi layer holds the minted handle and
/// passes it back to the sealing calls. There is no constructor from id text
/// and no export that computes a tag for an arbitrary id; after a restart the
/// only way back is [`NewItemId::resume`] with the tag minted at creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewItemId {
    id: String,
    tag: [u8; NEW_ITEM_TAG_LEN],
}

impl NewItemId {
    /// Mint a new owner (`O`) id (random version 4 UUID).
    pub fn owner(master: &MasterKey) -> Result<Self, CoreError> {
        Self::minted(new_owner_item_id()?, master)
    }

    /// Mint a new foreign (`F`) id (random version 8 UUID).
    pub fn foreign(master: &MasterKey) -> Result<Self, CoreError> {
        Self::minted(new_foreign_item_id()?, master)
    }

    fn minted(id: String, master: &MasterKey) -> Result<Self, CoreError> {
        let tag = new_item_tag(master, &id);
        Ok(Self { id, tag })
    }

    /// Resume a create session persisted before a restart (task 2275, L13).
    ///
    /// `tag` is the value [`tag`](Self::tag) returned when the id was minted and
    /// the client stored next to its upload session. A tampered tag, a tag for a
    /// different id, or an id with no tag (a server echo) is
    /// [`CoreError::InvalidInput`]. The comparison is constant time.
    pub fn resume(master: &MasterKey, id: &str, tag: &[u8]) -> Result<Self, CoreError> {
        parse_canonical(id)?;
        if tag.len() != NEW_ITEM_TAG_LEN {
            return Err(CoreError::InvalidInput(format!(
                "new-item tag must be {NEW_ITEM_TAG_LEN} bytes"
            )));
        }
        let expected = new_item_tag(master, id);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(CoreError::InvalidInput("new-item tag does not match this id".into()));
        }
        Ok(Self {
            id: id.to_string(),
            tag: expected,
        })
    }

    /// The canonical lowercase hyphenated id text.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// The resume tag minted with this id: HMAC-SHA256 under
    /// `HKDF(master, NEW_ITEM_TAG_INFO)` over the id's canonical text. Persist
    /// it with the upload session; never send it to a server.
    pub fn tag(&self) -> &[u8; NEW_ITEM_TAG_LEN] {
        &self.tag
    }
}

/// Tag for `id` under `master`'s new-item purpose key. Crate-internal: only
/// minting and [`NewItemId::resume`] may compute one.
fn new_item_tag(master: &MasterKey, id: &str) -> [u8; NEW_ITEM_TAG_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(NEW_ITEM_TAG_INFO, &mut *key)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    let mut mac = Hmac::<Sha256>::new_from_slice(&*key).expect("HMAC accepts a 32-byte key");
    mac.update(id.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; NEW_ITEM_TAG_LEN];
    tag.copy_from_slice(&out);
    tag
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

    fn master(byte: u8) -> MasterKey {
        MasterKey::from_bytes([byte; 32])
    }

    #[test]
    fn mint_returns_a_stable_tag_and_resume_rechecks_it() {
        let mk = master(0x11);
        let minted = NewItemId::owner(&mk).unwrap();
        assert_eq!(minted.tag().len(), NEW_ITEM_TAG_LEN);
        // Minting the same id twice is not possible; the tag is bound to the id.
        let resumed = NewItemId::resume(&mk, minted.as_str(), minted.tag()).unwrap();
        assert_eq!(resumed.as_str(), minted.as_str());
        assert_eq!(resumed.tag(), minted.tag());

        // A tampered tag is refused.
        let mut bad = *minted.tag();
        bad[0] ^= 1;
        assert!(matches!(
            NewItemId::resume(&mk, minted.as_str(), &bad),
            Err(CoreError::InvalidInput(_))
        ));
        // So is the tag of another id (and the id of another tag).
        let other = NewItemId::owner(&mk).unwrap();
        assert!(NewItemId::resume(&mk, minted.as_str(), other.tag()).is_err());
        assert!(NewItemId::resume(&mk, other.as_str(), minted.tag()).is_err());
        // A different master does not accept the tag.
        assert!(NewItemId::resume(&master(0x22), minted.as_str(), minted.tag()).is_err());
        // An id with no tag (a server echo) cannot be resumed.
        assert!(NewItemId::resume(&mk, minted.as_str(), &[]).is_err());
        // Nor can a non-canonical id.
        assert!(NewItemId::resume(&mk, "not-a-uuid", minted.tag()).is_err());
    }

    #[test]
    fn foreign_mint_also_carries_a_tag() {
        let mk = master(0x33);
        let minted = NewItemId::foreign(&mk).unwrap();
        assert!(is_foreign_item_id(minted.as_str()).unwrap());
        assert!(NewItemId::resume(&mk, minted.as_str(), minted.tag()).is_ok());
    }
}
