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

    /// The method's name or what the entry is, for `Method` and
    /// `Unsupported`.
    pub fn detail(&self) -> Option<&str> {
        match self {
            SkipReason::Method(detail) | SkipReason::Unsupported(detail) => Some(detail),
            _ => None,
        }
    }

    /// The reason from its binding string and detail; `None` for an
    /// unknown string.
    pub fn parse(reason: &str, detail: Option<&str>) -> Option<Self> {
        Some(match reason {
            "link" => SkipReason::Link,
            "device" => SkipReason::Device,
            "outside_folder" => SkipReason::OutsideFolder,
            "unusable_name" => SkipReason::UnusableName,
            "method" => SkipReason::Method(detail?.to_string()),
            "too_large" => SkipReason::TooLarge,
            "bomb" => SkipReason::Bomb,
            "mac_resource" => SkipReason::MacResource,
            "corrupt" => SkipReason::Corrupt,
            "other_password" => SkipReason::OtherPassword,
            "unsupported" => SkipReason::Unsupported(detail?.to_string()),
            _ => return None,
        })
    }
}

/// Why a whole archive is refused before anything is listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveRefusal {
    NotAnArchive,
    Foreign(super::detect::ForeignFormat),
    SelfExtracting,
    Spanned,
    StrongEncryption,
    Damaged,
    Truncated,
    TooMany,
    Bomb,
}

impl ArchiveRefusal {
    /// The binding string.
    pub const fn as_str(self) -> &'static str {
        match self {
            ArchiveRefusal::NotAnArchive => "not_an_archive",
            ArchiveRefusal::Foreign(_) => "foreign",
            ArchiveRefusal::SelfExtracting => "self_extracting",
            ArchiveRefusal::Spanned => "spanned",
            ArchiveRefusal::StrongEncryption => "strong_encryption",
            ArchiveRefusal::Damaged => "damaged",
            ArchiveRefusal::Truncated => "truncated",
            ArchiveRefusal::TooMany => "too_many",
            ArchiveRefusal::Bomb => "bomb",
        }
    }
}

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    File,
    Folder,
    Symlink,
    HardLink,
    Device,
    Other,
}

impl EntryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Folder => "folder",
            EntryKind::Symlink => "symlink",
            EntryKind::HardLink => "hard_link",
            EntryKind::Device => "device",
            EntryKind::Other => "other",
        }
    }
}

/// How an entry's contents are protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryCipher {
    None,
    ZipCrypto,
    /// WinZip AES: key bits 128, 192 or 256; AE-1 or AE-2.
    Aes {
        bits: u16,
        ae: u8,
    },
}

impl EntryCipher {
    pub const fn is_encrypted(self) -> bool {
        !matches!(self, EntryCipher::None)
    }
}

/// When an entry was last modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveTime {
    /// An absolute time (zip extended-timestamp or NTFS field, tar, gzip).
    Utc { unix_ms: i64 },
    /// A zone-less DOS time: shown as wall time.
    Local {
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    },
}

/// One entry of the listing. `index` is its position in
/// [`ArchiveListing::entries`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub index: u32,
    /// The decoded name as shown, control characters made visible.
    pub display_path: String,
    /// The path extraction writes; `None` when the name is skipped.
    pub path: Option<super::names::EntryPath>,
    pub kind: EntryKind,
    pub size: u64,
    pub compressed_size: u64,
    pub cipher: EntryCipher,
    pub modified: Option<ArchiveTime>,
    pub skip: Option<SkipReason>,
}

impl ArchiveEntry {
    /// The path a selection names this entry by, as the preview rows show
    /// it: its extraction path, or its shown name when it has none.
    pub fn selection_path(&self) -> String {
        self.path
            .as_ref()
            .map_or_else(|| self.display_path.clone(), |p| p.joined())
    }
}

/// Counts over the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArchiveTotals {
    pub files: u32,
    pub folders: u32,
    /// Declared uncompressed bytes of every file entry.
    pub bytes: u64,
    pub compressed_bytes: u64,
    /// Entries listed with a skip reason.
    pub skipped: u32,
}

/// Whether the archive's files need a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protection {
    None,
    Some,
    All,
}

impl Protection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Protection::None => "none",
            Protection::Some => "some",
            Protection::All => "all",
        }
    }
}

/// What an archive holds, as core lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveListing {
    pub format: super::detect::ArchiveFormat,
    pub entries: Vec<ArchiveEntry>,
    pub totals: ArchiveTotals,
    pub protection: Protection,
    pub uses_zipcrypto: bool,
    /// `false` when a tgz/gz listing stopped at the platform's scan limit.
    pub complete: bool,
}
