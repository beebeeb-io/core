//! An archive's password (spec §7): held for one session, wiped on drop,
//! never printed.

use zeroize::Zeroizing;

/// The password the person typed for an archive. Not `Clone`; its `Debug`
/// prints `ArchivePassword(..)`; it has no `Display`. It lives for one
/// preview or one extraction and is wiped when dropped.
pub struct ArchivePassword(
    #[expect(dead_code, reason = "read by the zip decoders (plan Tasks 5-6)")] Zeroizing<String>,
);

impl ArchivePassword {
    pub fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }
}

impl std::fmt::Debug for ArchivePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchivePassword(..)")
    }
}
