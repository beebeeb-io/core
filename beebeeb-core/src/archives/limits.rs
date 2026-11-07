//! Spec §6.2's limits. They protect the device and the person's time, so
//! they are core constants, not server-owned. The server owns the quota only
//! (free bytes), which the planner reads and every upload re-checks.

use beebeeb_types::limits::MAX_FFI_LIST_LENGTH;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Entries in one archive, implied folders included.
pub const MAX_ENTRIES: usize = MAX_FFI_LIST_LENGTH;
/// The zip central directory, read whole before anything is listed.
pub const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 32 * MIB;
/// One pax header set, or one GNU long name or link name.
pub const MAX_TAR_META_BYTES: u64 = MIB;
/// One entry's uncompressed size on native and the mobile app.
pub const MAX_ENTRY_BYTES_NATIVE: u64 = 64 * GIB;
/// One entry's uncompressed size in the browser (Blob staging).
pub const MAX_ENTRY_BYTES_BROWSER: u64 = 2 * GIB;
/// Everything one extraction writes, uncompressed.
pub const MAX_EXTRACTION_BYTES: u64 = 256 * GIB;
/// Output/input ratio above which a large entry or stream is a bomb.
pub const BOMB_RATIO: u64 = 1_000;
/// The ratio applies only past this much output.
pub const BOMB_RATIO_FLOOR_BYTES: u64 = GIB;
/// Path components below the destination folder.
pub const MAX_DEPTH: usize = 64;
/// One path component, in UTF-8 bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// A whole entry path, in UTF-8 bytes.
pub const MAX_PATH_BYTES: usize = 4096;
/// Decompressed stream a tgz/gz listing scans, per platform.
pub const PREVIEW_SCAN_BYTES_NATIVE: u64 = 2 * GIB;
pub const PREVIEW_SCAN_BYTES_BROWSER: u64 = 512 * MIB;
pub const PREVIEW_SCAN_BYTES_MOBILE_APP: u64 = 256 * MIB;
/// Times a zip parse may restart after a byte miss before it is damaged.
pub const MAX_PARSE_RESTARTS: u32 = 8;
/// Compressed bytes kept supplied ahead of an entry decoder.
pub const PULL_AHEAD_BYTES: u64 = 64 * KIB;
/// Largest plaintext piece an entry reader yields.
pub const PIECE_BYTES: usize = 64 * 1024;
/// Bytes read from a file's start to detect its format.
pub const DETECT_HEAD_BYTES: u64 = 512;
/// The zip tail window: the end record (22) + the longest comment (65,535)
/// + the ZIP64 locator (20) + the ZIP64 end record (56).
pub const ZIP_TAIL_WINDOW: u64 = 65_557 + 20 + 56;
/// Native drivers stop stepping while this much staged plaintext waits
/// for its uploads.
pub const NATIVE_STAGING_AHEAD_BYTES: u64 = GIB;
/// Web drivers stop stepping while this many staged entries wait.
pub const BROWSER_STAGED_ENTRIES: usize = 2;
