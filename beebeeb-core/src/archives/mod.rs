//! Archives: list, preview and extract zip, tar, tgz and gz (task 2380).
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
pub mod limits;
pub mod model;
pub mod names;
pub mod platform;
pub mod words;

pub use detect::{ArchiveFormat, Detection, ForeignFormat, detect, detect_gzip_inner};
pub use model::SkipReason;
pub use names::{EntryPath, RawName, decode_name, display_name, entry_path};
pub use platform::ArchivePlatform;
pub use words::{ArchiveKey, ArchiveText, archive_text};
