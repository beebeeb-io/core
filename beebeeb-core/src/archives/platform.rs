//! The platforms an archive is read on, and what each can afford.

use beebeeb_types::limits::MemoryBudget;

use super::limits;
use crate::media::PreviewPlatform;

/// Where the reader runs. The File Provider / share extensions never read
/// archives (spec §8), so there is no extension platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchivePlatform {
    /// Desktop and the CLI.
    Native,
    /// The web app (wasm).
    Browser,
    /// The iOS app.
    MobileApp,
}

impl ArchivePlatform {
    pub const ALL: [ArchivePlatform; 3] = [
        ArchivePlatform::Native,
        ArchivePlatform::Browser,
        ArchivePlatform::MobileApp,
    ];

    /// The binding string: `"native" | "browser" | "mobile_app"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ArchivePlatform::Native => "native",
            ArchivePlatform::Browser => "browser",
            ArchivePlatform::MobileApp => "mobile_app",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == text)
    }

    /// The platform's memory budget; `archive_output_bytes` caps Open.
    pub const fn budget(self) -> MemoryBudget {
        match self {
            ArchivePlatform::Native => MemoryBudget::NATIVE,
            ArchivePlatform::Browser => MemoryBudget::BROWSER,
            ArchivePlatform::MobileApp => MemoryBudget::MOBILE_APP,
        }
    }

    /// Largest uncompressed entry this platform extracts.
    pub const fn max_entry_bytes(self) -> u64 {
        match self {
            ArchivePlatform::Native | ArchivePlatform::MobileApp => limits::MAX_ENTRY_BYTES_NATIVE,
            ArchivePlatform::Browser => limits::MAX_ENTRY_BYTES_BROWSER,
        }
    }

    /// Decompressed bytes a tgz/gz listing scans before it is incomplete.
    pub const fn preview_scan_bytes(self) -> u64 {
        match self {
            ArchivePlatform::Native => limits::PREVIEW_SCAN_BYTES_NATIVE,
            ArchivePlatform::Browser => limits::PREVIEW_SCAN_BYTES_BROWSER,
            ArchivePlatform::MobileApp => limits::PREVIEW_SCAN_BYTES_MOBILE_APP,
        }
    }

    /// iOS suspends a backgrounded app, and reading the archive stops with
    /// it, so only the mobile app says "keep Beebeeb open".
    pub const fn keep_open_notice(self) -> bool {
        matches!(self, ArchivePlatform::MobileApp)
    }

    /// The chunk plan this platform's uploads use (for stored sizes).
    pub const fn chunk_profile(self) -> beebeeb_types::ChunkProfile {
        match self {
            ArchivePlatform::Native => beebeeb_types::ChunkProfile::Desktop,
            ArchivePlatform::Browser => beebeeb_types::ChunkProfile::Web,
            ArchivePlatform::MobileApp => beebeeb_types::ChunkProfile::Mobile,
        }
    }

    /// The row of core's preview table that decides what Open may show.
    pub const fn preview_platform(self) -> PreviewPlatform {
        match self {
            ArchivePlatform::Native => PreviewPlatform::Desktop,
            ArchivePlatform::Browser => PreviewPlatform::Web,
            ArchivePlatform::MobileApp => PreviewPlatform::Mobile,
        }
    }
}
