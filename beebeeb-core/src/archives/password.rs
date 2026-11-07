//! An archive's password (spec §7): held for one session, wiped on drop,
//! never printed.

use zeroize::Zeroizing;

use super::names::encode_cp437;
use super::source::ByteRange;

/// The password the person typed for an archive. Not `Clone`; its `Debug`
/// prints `ArchivePassword(..)`; it has no `Display`. It lives for one
/// preview or one extraction and is wiped when dropped.
///
/// It cannot be copied:
///
/// ```compile_fail,E0599
/// use beebeeb_core::archives::ArchivePassword;
/// let password = ArchivePassword::new("typed by the person".to_string());
/// let copy = password.clone();
/// ```
pub struct ArchivePassword(Zeroizing<String>);

impl ArchivePassword {
    pub fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }

    /// The byte encodings to try, in order, each wiped when dropped: the
    /// UTF-8 bytes, then, when the password has a non-ASCII character, its
    /// CP437 bytes once (old Windows ZipCrypto tools used the OEM code
    /// page). No trimming and no normalisation: the password is used as
    /// typed.
    pub(crate) fn candidates(&self) -> Vec<Zeroizing<Vec<u8>>> {
        let mut candidates = vec![Zeroizing::new(self.0.as_bytes().to_vec())];
        if !self.0.is_ascii()
            && let Some(cp437) = encode_cp437(&self.0)
        {
            candidates.push(cp437);
        }
        candidates
    }
}

impl std::fmt::Debug for ArchivePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchivePassword(..)")
    }
}

/// What a password check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordStep {
    /// Supply these bytes to the source, then check again.
    NeedBytes(ByteRange),
    /// The password opens the entry (its quick check passed; the entry's
    /// own CRC or authentication code still decides at the end).
    Accepted,
    /// The password does not open the entry.
    Wrong,
    /// The entry is not protected.
    NotNeeded,
    /// The source failed (a disk or network error): the password was not
    /// checked.
    Io(String),
}
