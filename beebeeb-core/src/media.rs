//! Shared media/MIME utilities. All clients use these instead of
//! reimplementing MIME detection and classification.

/// Returns true if the MIME type represents media (image or video).
/// Single source of truth for all clients.
pub fn is_media(mime_type: Option<&str>) -> bool {
    match mime_type {
        Some(m) => m.starts_with("image/") || m.starts_with("video/"),
        None => false,
    }
}

/// Returns true if the MIME type can be previewed in-app.
/// Covers: images, video, audio, PDF, text, markdown, code.
pub fn is_previewable(mime_type: Option<&str>) -> bool {
    match mime_type {
        None => false,
        Some(m) => {
            m.starts_with("image/")
                || m.starts_with("video/")
                || m.starts_with("audio/")
                || m.starts_with("text/")
                || m == "application/pdf"
                || m == "application/json"
                || m == "application/xml"
                || m == "application/javascript"
        }
    }
}

/// Returns true if the file extension indicates a previewable file.
/// Use when MIME type is unknown (encrypted).
///
/// This is the `Mobile` column of the preview-platform table in this module,
/// unchanged: `test-vectors/consolidation/preview_platforms.json` fails if the
/// two ever drift.
pub fn is_previewable_by_extension(filename: &str) -> bool {
    let ext = match filename.rsplit('.').next() {
        Some(e) => e.to_lowercase(),
        None => return false,
    };
    matches!(
        ext.as_str(),
        // Images
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "svg" | "bmp" | "ico" | "avif" | "heic" | "heif" | "tiff" | "tif" |
        // Video
        "mp4" | "mov" | "webm" | "mkv" | "avi" |
        // Audio
        "mp3" | "flac" | "wav" | "aac" | "ogg" | "m4a" | "opus" | "wma" |
        // PDF
        "pdf" |
        // Text / Markdown
        "txt" | "md" | "markdown" | "csv" | "log" | "rtf" |
        // Office
        "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" |
        // Archives
        "tar" | "gz" | "tgz" |
        // Code
        "py" | "js" | "jsx" | "ts" | "tsx" | "rs" | "go" | "rb" | "java" | "kt" | "swift" |
        "c" | "cpp" | "h" | "hpp" | "cs" | "php" | "sh" | "bash" | "zsh" |
        "html" | "htm" | "css" | "scss" | "less" |
        "vue" | "svelte" | "astro" |
        "dart" | "r" | "ex" | "exs" | "zig" | "nim" | "v" |
        "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "conf" |
        "sql" | "graphql" | "proto" | "cmake" | "dockerfile" | "makefile"
    )
}

/// One preview decision per row of a name list.
///
/// `Vec<bool>` is bit-packed by Rust, so 10,000 names cost one FFI/wasm
/// crossing and about 1.25 KB instead of a crossing per row.
pub type BitSet = Vec<bool>;

/// Answers [`is_previewable_by_extension`] for a whole list in one call.
///
/// The result is aligned with `names`: `result[i]` is the answer for
/// `names[i]`, byte-for-byte the same answer the single-name predicate gives.
/// Clients with an encrypted listing use this so a list of files costs one
/// boundary crossing instead of one per row.
pub fn previewable_batch(names: &[String]) -> BitSet {
    names.iter().map(|name| is_previewable_by_extension(name)).collect()
}

// ---------------------------------------------------------------------------
// Which client can render a preview in-app
// ---------------------------------------------------------------------------

/// A client that renders previews in-app.
///
/// Consolidation merged three different allowlists into one function, and the
/// merge must never narrow a client: each platform keeps exactly the extensions
/// it could render before. The table below is the one place those columns live;
/// [`is_previewable_by_extension_for`] and [`previewable_batch_for`] read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PreviewPlatform {
    /// The web app (`repos/web`).
    Web,
    /// The desktop app (`repos/desktop`, tray/preview file types).
    Desktop,
    /// The mobile apps (iOS/Android) — the set [`is_previewable_by_extension`]
    /// has always answered.
    Mobile,
}

impl PreviewPlatform {
    /// The platform a caller names on a binding boundary: `"web"`, `"desktop"`
    /// or `"mobile"`. Anything else is `None`, so a binding reports an error
    /// instead of silently answering for a different client.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "web" => Some(Self::Web),
            "desktop" => Some(Self::Desktop),
            "mobile" => Some(Self::Mobile),
            _ => None,
        }
    }

    /// The column this platform reads in [`preview_platform_flags`].
    const fn bit(self) -> u8 {
        match self {
            Self::Web => WEB,
            Self::Desktop => DESKTOP,
            Self::Mobile => MOBILE,
        }
    }
}

const WEB: u8 = 1 << 0;
const DESKTOP: u8 = 1 << 1;
const MOBILE: u8 = 1 << 2;

/// The one preview table: extension -> the platforms that render it in-app.
///
/// Every column is a client's current list, not a union and not a policy:
///
/// - `WEB`: web's `PREVIEWABLE_EXTENSIONS` at `aee93c8e^:src/lib/preview.ts`
///   (78 extensions), read before the web lane switched to core. Web also
///   accepts a whole-MIME-type pass (`image/*`, `video/*`, `audio/*`, `text/*`,
///   PDF, and the docx/xlsx/pptx/ppt MIME types) — that half is
///   [`is_previewable`] and is platform-neutral, so it is not repeated here.
/// - `DESKTOP`: desktop's `getFileType` table in `desktop/src/WindowsTray.tsx`
///   (88 extensions: image, video, audio, code, archive, plus `pdf`). No Rust
///   side feeds that list.
/// - `MOBILE`: [`is_previewable_by_extension`] (90 extensions), unchanged.
///
/// `test-vectors/consolidation/preview_platforms.json` carries one expected
/// value per platform for every extension of the 123-entry union, and fails if
/// any column drifts from its source list.
fn preview_platform_flags(ext: &str) -> u8 {
    match ext {
        "7z" => DESKTOP,
        "aac" => WEB | DESKTOP | MOBILE,
        "aif" => WEB,
        "aiff" => WEB | DESKTOP,
        "alac" => WEB,
        "arw" => WEB | DESKTOP,
        "asm" => DESKTOP,
        "astro" => DESKTOP | MOBILE,
        "avi" => DESKTOP | MOBILE,
        "avif" => WEB | DESKTOP | MOBILE,
        "bash" => DESKTOP | MOBILE,
        "bmp" => WEB | DESKTOP | MOBILE,
        "bz2" => DESKTOP,
        "c" => WEB | DESKTOP | MOBILE,
        "cmake" => MOBILE,
        "conf" => MOBILE,
        "cpp" => WEB | DESKTOP | MOBILE,
        "cr2" => WEB | DESKTOP,
        "cr3" => WEB | DESKTOP,
        "cs" => WEB | DESKTOP | MOBILE,
        "css" => WEB | DESKTOP | MOBILE,
        "csv" => WEB | MOBILE,
        "dart" => MOBILE,
        "dmg" => DESKTOP,
        "dng" => WEB | DESKTOP,
        "dockerfile" => WEB | MOBILE,
        "docx" => WEB | MOBILE,
        "ex" => MOBILE,
        "exs" => MOBILE,
        "flac" => WEB | DESKTOP | MOBILE,
        "flv" => DESKTOP,
        "gif" => WEB | DESKTOP | MOBILE,
        "go" => WEB | DESKTOP | MOBILE,
        "graphql" => DESKTOP | MOBILE,
        "gz" => DESKTOP | MOBILE,
        "h" => WEB | DESKTOP | MOBILE,
        "heic" => WEB | DESKTOP | MOBILE,
        "heif" => WEB | DESKTOP | MOBILE,
        "hevc" => WEB | DESKTOP,
        "hpp" => DESKTOP | MOBILE,
        "htm" => DESKTOP | MOBILE,
        "html" => WEB | DESKTOP | MOBILE,
        "ico" => WEB | DESKTOP | MOBILE,
        "ini" => WEB | MOBILE,
        "iso" => DESKTOP,
        "java" => WEB | DESKTOP | MOBILE,
        "jpeg" => WEB | DESKTOP | MOBILE,
        "jpg" => WEB | DESKTOP | MOBILE,
        "js" => WEB | DESKTOP | MOBILE,
        "json" => WEB | MOBILE,
        "jsx" => WEB | DESKTOP | MOBILE,
        "key" => WEB,
        "kt" => WEB | DESKTOP | MOBILE,
        "less" => DESKTOP | MOBILE,
        "log" => WEB | MOBILE,
        "lua" => DESKTOP,
        "lz" => DESKTOP,
        "m4a" => WEB | DESKTOP | MOBILE,
        "m4v" => DESKTOP,
        "makefile" => MOBILE,
        "markdown" => MOBILE,
        "md" => WEB | MOBILE,
        "mkv" => WEB | DESKTOP | MOBILE,
        "mov" => WEB | DESKTOP | MOBILE,
        "mp3" => WEB | DESKTOP | MOBILE,
        "mp4" => WEB | DESKTOP | MOBILE,
        "nef" => WEB | DESKTOP,
        "nim" => MOBILE,
        "odp" => WEB | MOBILE,
        "ods" => MOBILE,
        "odt" => MOBILE,
        "oga" => WEB,
        "ogg" => WEB | DESKTOP | MOBILE,
        "opus" => WEB | DESKTOP | MOBILE,
        "orf" => WEB | DESKTOP,
        "pdf" => WEB | DESKTOP | MOBILE,
        "php" => WEB | DESKTOP | MOBILE,
        "png" => WEB | DESKTOP | MOBILE,
        "ppt" => WEB,
        "pptx" => WEB | MOBILE,
        "proto" => DESKTOP | MOBILE,
        "py" => WEB | DESKTOP | MOBILE,
        "r" => DESKTOP | MOBILE,
        "raf" => WEB | DESKTOP,
        "rar" => DESKTOP,
        "rb" => WEB | DESKTOP | MOBILE,
        "rs" => WEB | DESKTOP | MOBILE,
        "rtf" => MOBILE,
        "rw2" => WEB | DESKTOP,
        "sass" => DESKTOP,
        "scala" => DESKTOP,
        "scss" => DESKTOP | MOBILE,
        "sh" => WEB | DESKTOP | MOBILE,
        "sql" => WEB | DESKTOP | MOBILE,
        "svelte" => DESKTOP | MOBILE,
        "svg" => WEB | DESKTOP | MOBILE,
        "swift" => WEB | DESKTOP | MOBILE,
        "tar" => DESKTOP | MOBILE,
        "tgz" => MOBILE,
        "tif" => WEB | DESKTOP | MOBILE,
        "tiff" => WEB | DESKTOP | MOBILE,
        "toml" => WEB | MOBILE,
        "ts" => WEB | DESKTOP | MOBILE,
        "tsv" => WEB,
        "tsx" => WEB | DESKTOP | MOBILE,
        "txt" => WEB | MOBILE,
        "v" => MOBILE,
        "vue" => DESKTOP | MOBILE,
        "wav" => WEB | DESKTOP | MOBILE,
        "webm" => WEB | DESKTOP | MOBILE,
        "webp" => WEB | DESKTOP | MOBILE,
        "wma" => WEB | DESKTOP | MOBILE,
        "wmv" => DESKTOP,
        "xls" => WEB,
        "xlsx" => WEB | MOBILE,
        "xml" => WEB | MOBILE,
        "xz" => DESKTOP,
        "yaml" => WEB | MOBILE,
        "yml" => MOBILE,
        "zig" => DESKTOP | MOBILE,
        "zip" => WEB | DESKTOP,
        "zsh" => DESKTOP | MOBILE,
        "zst" => DESKTOP,
        _ => 0,
    }
}

/// The extension a filename is keyed by: the text after the last dot,
/// lowercased. A name with no dot keys by the whole name (so `Dockerfile`
/// matches `dockerfile`, exactly as [`is_previewable_by_extension`] does).
fn preview_extension(filename: &str) -> String {
    match filename.rsplit('.').next() {
        Some(ext) => ext.to_lowercase(),
        None => String::new(),
    }
}

/// [`is_previewable_by_extension`] for one named platform.
///
/// Same filename rule and the same case folding; only the column differs. The
/// answer for [`PreviewPlatform::Mobile`] is exactly what
/// [`is_previewable_by_extension`] returns.
pub fn is_previewable_by_extension_for(filename: &str, platform: PreviewPlatform) -> bool {
    preview_platform_flags(&preview_extension(filename)) & platform.bit() != 0
}

/// [`previewable_batch`] for one named platform: one bit per name, in order.
///
/// `result[i]` is [`is_previewable_by_extension_for`] for `names[i]` and
/// `platform`, so a listing costs one boundary crossing per platform.
pub fn previewable_batch_for(names: &[String], platform: PreviewPlatform) -> BitSet {
    names
        .iter()
        .map(|name| is_previewable_by_extension_for(name, platform))
        .collect()
}

/// Guess the MIME type from a filename extension.
/// Returns None for unknown extensions.
pub fn guess_mime_type(filename: &str) -> Option<&'static str> {
    let ext = filename.rsplit('.').next()?.to_lowercase();
    match ext.as_str() {
        // Images
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "svg" => Some("image/svg+xml"),
        "bmp" => Some("image/bmp"),
        "ico" => Some("image/x-icon"),
        "tiff" | "tif" => Some("image/tiff"),
        "heic" | "heif" => Some("image/heic"),
        "avif" => Some("image/avif"),
        // Video
        "mp4" | "m4v" => Some("video/mp4"),
        "mov" => Some("video/quicktime"),
        "avi" => Some("video/x-msvideo"),
        "mkv" => Some("video/x-matroska"),
        "webm" => Some("video/webm"),
        "wmv" => Some("video/x-ms-wmv"),
        "flv" => Some("video/x-flv"),
        // Audio
        "mp3" => Some("audio/mpeg"),
        "flac" => Some("audio/flac"),
        "ogg" | "oga" => Some("audio/ogg"),
        "wav" => Some("audio/wav"),
        "aac" => Some("audio/aac"),
        "m4a" => Some("audio/mp4"),
        "wma" => Some("audio/x-ms-wma"),
        "opus" => Some("audio/opus"),
        // Documents
        "pdf" => Some("application/pdf"),
        "doc" => Some("application/msword"),
        "docx" => Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xls" => Some("application/vnd.ms-excel"),
        "xlsx" => Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "ppt" => Some("application/vnd.ms-powerpoint"),
        "pptx" => Some("application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "odt" => Some("application/vnd.oasis.opendocument.text"),
        "ods" => Some("application/vnd.oasis.opendocument.spreadsheet"),
        "odp" => Some("application/vnd.oasis.opendocument.presentation"),
        "txt" | "text" => Some("text/plain"),
        "csv" => Some("text/csv"),
        "md" | "markdown" => Some("text/markdown"),
        "json" => Some("application/json"),
        "xml" => Some("application/xml"),
        "html" | "htm" => Some("text/html"),
        "css" => Some("text/css"),
        "js" => Some("application/javascript"),
        "vue" | "svelte" | "astro" => Some("text/plain"),
        "kt" => Some("text/x-kotlin"),
        "swift" => Some("text/x-swift"),
        "cs" => Some("text/x-csharp"),
        "dart" => Some("text/x-dart"),
        "r" => Some("text/x-r"),
        "ex" | "exs" => Some("text/x-elixir"),
        "zig" => Some("text/x-zig"),
        "nim" => Some("text/x-nim"),
        "v" => Some("text/x-v"),
        "proto" => Some("text/x-protobuf"),
        "cmake" => Some("text/x-cmake"),
        // Archives
        "zip" => Some("application/zip"),
        "gz" | "gzip" | "tgz" => Some("application/gzip"),
        "tar" => Some("application/x-tar"),
        "rar" => Some("application/vnd.rar"),
        "7z" => Some("application/x-7z-compressed"),
        _ => None,
    }
}
