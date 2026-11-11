//! Archives: list, preview and extract zip, tar, tgz and gz.
//!
//! One sans-I/O reader for every client (spec A1): the reader asks its
//! driver for byte ranges and never does I/O itself, so the native drivers
//! (which answer at once) and the web driver (which answers later) run the
//! same code. Core decides what is listed, what is refused, every name and
//! every word; drivers only read bytes, create folders and upload files.
//!
//! The format comes from magic bytes, never the extension (A2). The
//! extension only decides whether the preview and Extract are offered.

pub mod detect;
pub mod extract;
mod gzip;
mod inflate;
pub mod limits;
mod listing;
pub mod model;
pub mod names;
pub mod password;
pub mod plan;
pub mod platform;
pub mod preview;
pub mod session;
pub mod source;
mod tar;
mod winzip_aes;
pub mod words;
mod zip;
mod zipcrypto;

pub use detect::{ArchiveFormat, Detection, ForeignFormat, detect, detect_gzip_inner};
pub use extract::{
    ArchiveIdentity, ExtractOutcome, ExtractProgress, ExtractStep, ExtractSummary, Extraction, FailReason,
};
pub use model::{
    ArchiveEntry, ArchiveListing, ArchiveRefusal, ArchiveTime, ArchiveTotals, EntryCipher, EntryKind, Protection,
    SkipReason,
};
pub use names::{EntryPath, RawName, decode_name, display_name, entry_path};
pub use password::{ArchivePassword, PasswordStep};
pub use plan::{
    DestinationInfo, ExtractRequest, ExtractionPlan, NodeKind, PlanRefusal, PlanTarget, PlannedNode, Selection,
    destination_stem, plan_extraction,
};
pub use platform::ArchivePlatform;
pub use preview::{
    ActionKind, ArchivePreviewModel, DestinationKind, ListingState, PreviewAction, PreviewInput, PreviewRow,
    PreviewState, archive_preview,
};
pub use session::{ArchiveSession, EntryReader, EntryStream, PieceStep, SessionStep};
pub use source::{ByteRange, ByteSource, ReadSeekSource, SourceError, SuppliedBytes};
pub use words::{ArchiveKey, ArchiveText, archive_text};
