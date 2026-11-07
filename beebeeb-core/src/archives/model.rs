//! The listing's types: what an archive holds, and why an entry is skipped.

/// Why an entry is listed but not extracted. A skipped entry is shown with
/// its note (spec §9), never hidden.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// A symbolic or hard link.
    Link,
    /// A device, FIFO or other special file.
    Device,
    /// A `..` component: it points outside the destination (zip-slip).
    OutsideFolder,
    /// A name core cannot decode or that no platform can store.
    UnusableName,
    /// A compression method Beebeeb does not decode (its name).
    Method(String),
    /// Larger than this platform extracts.
    TooLarge,
    /// Expands far more than a normal file.
    Bomb,
    /// `__MACOSX/` resource data.
    MacResource,
    /// Its CRC-32 or authentication code did not match.
    Corrupt,
    /// It did not open with the password that opened the others.
    OtherPassword,
    /// Anything else not extracted (what it is).
    Unsupported(String),
}

impl SkipReason {
    /// The binding string.
    pub fn as_str(&self) -> &'static str {
        match self {
            SkipReason::Link => "link",
            SkipReason::Device => "device",
            SkipReason::OutsideFolder => "outside_folder",
            SkipReason::UnusableName => "unusable_name",
            SkipReason::Method(_) => "method",
            SkipReason::TooLarge => "too_large",
            SkipReason::Bomb => "bomb",
            SkipReason::MacResource => "mac_resource",
            SkipReason::Corrupt => "corrupt",
            SkipReason::OtherPassword => "other_password",
            SkipReason::Unsupported(_) => "unsupported",
        }
    }
}
