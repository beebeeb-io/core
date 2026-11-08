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
pub struct ArchivePassword {
    secret: Zeroizing<String>,
    /// The encoding an entry's own CRC or authentication code proved;
    /// tried first from then on.
    proven: Option<Encoding>,
}

/// One way to turn the typed password into bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Cp437,
}

impl ArchivePassword {
    pub fn new(secret: String) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            proven: None,
        }
    }

    /// The encodings to try, in order: the proven one first, then the
    /// UTF-8 bytes, then, when the password has a non-ASCII character, its
    /// CP437 bytes (old Windows ZipCrypto tools used the OEM code page).
    fn order(&self) -> Vec<Encoding> {
        let mut order = vec![Encoding::Utf8];
        if !self.secret.is_ascii() {
            order.push(Encoding::Cp437);
        }
        if self.proven == Some(Encoding::Cp437) {
            order.reverse();
        }
        order
    }

    /// The byte encodings to try, in [`Self::order`], each wiped when
    /// dropped. No trimming and no normalisation: the password is used as
    /// typed. A CP437 encoding the password cannot have is left out.
    pub(crate) fn candidates(&self) -> Vec<Zeroizing<Vec<u8>>> {
        self.order()
            .into_iter()
            .filter_map(|encoding| match encoding {
                Encoding::Utf8 => Some(Zeroizing::new(self.secret.as_bytes().to_vec())),
                Encoding::Cp437 => encode_cp437(&self.secret),
            })
            .collect()
    }

    /// An entry read with candidate `tried` (an index into this
    /// password's [`Self::candidates`]) passed its own CRC or
    /// authentication code: try that encoding first from now on.
    pub(crate) fn note_proven(&mut self, tried: usize) {
        let available: Vec<Encoding> = self
            .order()
            .into_iter()
            .filter(|encoding| *encoding == Encoding::Utf8 || encode_cp437(&self.secret).is_some())
            .collect();
        if let Some(encoding) = available.get(tried) {
            self.proven = Some(*encoding);
        }
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
    /// The entry's headers are damaged (they disagree with the central
    /// directory, or end early): the password cannot be judged, and
    /// reading the entry reports it damaged.
    Damaged,
    /// The entry is not protected.
    NotNeeded,
    /// The source failed (a disk or network error): the password was not
    /// checked.
    Io(String),
}
