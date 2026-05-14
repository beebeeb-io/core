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
pub fn is_previewable_by_extension(filename: &str) -> bool {
    let ext = match filename.rsplit('.').next() {
        Some(e) => e.to_lowercase(),
        None => return false,
    };
    matches!(ext.as_str(),
        // Images
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "svg" | "bmp" | "ico" | "avif" | "heic" | "tiff" | "tif" |
        // Video
        "mp4" | "mov" | "webm" | "mkv" | "avi" |
        // Audio
        "mp3" | "flac" | "wav" | "aac" | "ogg" | "m4a" | "opus" | "wma" |
        // PDF
        "pdf" |
        // Text / Markdown
        "txt" | "md" | "markdown" | "csv" | "log" | "rtf" |
        // Code
        "py" | "js" | "jsx" | "ts" | "tsx" | "rs" | "go" | "rb" | "java" | "kt" | "swift" |
        "c" | "cpp" | "h" | "hpp" | "cs" | "php" | "sh" | "bash" | "zsh" |
        "html" | "htm" | "css" | "scss" | "less" |
        "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "conf" |
        "sql" | "graphql" | "proto" | "dockerfile" | "makefile"
    )
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
        "txt" | "text" => Some("text/plain"),
        "csv" => Some("text/csv"),
        "md" | "markdown" => Some("text/markdown"),
        "json" => Some("application/json"),
        "xml" => Some("application/xml"),
        "html" | "htm" => Some("text/html"),
        "css" => Some("text/css"),
        "js" => Some("application/javascript"),
        // Archives
        "zip" => Some("application/zip"),
        "gz" | "gzip" => Some("application/gzip"),
        "tar" => Some("application/x-tar"),
        "rar" => Some("application/vnd.rar"),
        "7z" => Some("application/x-7z-compressed"),
        _ => None,
    }
}
