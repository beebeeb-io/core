//! Archive parsing — TAR header reading and gzip decompression.
//!
//! Mirrors the JS implementations in the mobile app (`ArchiveRenderer.tsx`)
//! but runs natively via UniFFI/WASM. Supports:
//!
//! - `.tar` — 512-byte header block parsing
//! - `.gz` — gzip decompression via `flate2`
//! - `.tgz` / `.tar.gz` — decompress then parse as TAR
//!
//! ZIP parsing is handled separately by the `zip` crate (see `zip.rs`).

use flate2::read::GzDecoder;
use std::io::Read;

use crate::CoreError;

/// A single entry inside a TAR archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Full path inside the archive (e.g. "src/main.rs").
    pub name: String,
    /// Uncompressed size in bytes.
    pub size: u64,
    /// Whether this entry is a directory.
    pub is_directory: bool,
}

// ---------------------------------------------------------------------------
// TAR parser
// ---------------------------------------------------------------------------

/// TAR header offsets and sizes per POSIX / UStar spec.
const TAR_BLOCK_SIZE: usize = 512;
const NAME_OFFSET: usize = 0;
const NAME_LEN: usize = 100;
const SIZE_OFFSET: usize = 124;
const SIZE_LEN: usize = 12;
const TYPEFLAG_OFFSET: usize = 156;
const PREFIX_OFFSET: usize = 345;
const PREFIX_LEN: usize = 155;

/// Parse a TAR file from raw bytes and return the list of entries.
///
/// TAR format: 512-byte header blocks followed by `ceil(size/512)*512` bytes
/// of file data. An all-zero 512-byte block signals end-of-archive.
pub fn list_tar_entries(data: &[u8]) -> Result<Vec<ArchiveEntry>, CoreError> {
    let mut entries = Vec::new();
    let mut offset: usize = 0;

    while offset + TAR_BLOCK_SIZE <= data.len() {
        // Check for end-of-archive (all-zero block)
        if data[offset..offset + TAR_BLOCK_SIZE].iter().all(|&b| b == 0) {
            break;
        }

        let name = read_null_string(data, offset + NAME_OFFSET, NAME_LEN);
        let size_str = read_null_string(data, offset + SIZE_OFFSET, SIZE_LEN);
        let typeflag = data[offset + TYPEFLAG_OFFSET];
        let prefix = read_null_string(data, offset + PREFIX_OFFSET, PREFIX_LEN);

        let full_name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };

        let size = u64::from_str_radix(&size_str, 8).unwrap_or(0);
        let is_directory = typeflag == b'5' || full_name.ends_with('/');

        // Skip the "." and "./" pseudo-entries
        if !full_name.is_empty() && full_name != "." && full_name != "./" {
            let clean_name = full_name.trim_end_matches('/').to_string();
            entries.push(ArchiveEntry {
                name: clean_name,
                size: if is_directory { 0 } else { size },
                is_directory,
            });
        }

        // Advance past header + data (data padded to 512-byte boundary)
        let data_blocks = if size > 0 {
            (size as usize).div_ceil(TAR_BLOCK_SIZE)
        } else {
            0
        };
        offset += TAR_BLOCK_SIZE + data_blocks * TAR_BLOCK_SIZE;
    }

    Ok(entries)
}

/// Read a null-terminated string from a byte slice.
fn read_null_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = data.len().min(offset + max_len);
    let slice = &data[offset..end];
    let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..null_pos]).trim().to_string()
}

// ---------------------------------------------------------------------------
// Gzip decompression
// ---------------------------------------------------------------------------

/// Maximum bytes we will decompress from a gzip stream.
///
/// Prevents zip-bomb / OOM DoS: a tiny `.gz` can decompress to gigabytes.
/// 1 GiB is large enough for legitimate archives but small enough that an
/// adversarial input cannot exhaust memory on a typical client device.
const MAX_DECOMPRESS_BYTES: u64 = 1024 * 1024 * 1024;

/// Decompress gzip-compressed data. Returns the decompressed bytes.
///
/// The output is bounded at [`MAX_DECOMPRESS_BYTES`]; inputs that decompress
/// to more than that are rejected with [`CoreError::Io`] rather than allowed
/// to balloon the process memory.
pub fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut decoder = GzDecoder::new(data).take(MAX_DECOMPRESS_BYTES);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| CoreError::Io(format!("gzip decompression failed: {e}")))?;
    // `Read::take` silently stops at the limit; if we hit exactly the cap the
    // stream may have been truncated. Treat that as an error rather than
    // returning partial data the caller will try to parse.
    if result.len() as u64 == MAX_DECOMPRESS_BYTES {
        return Err(CoreError::Io(format!(
            "gzip decompression exceeded {MAX_DECOMPRESS_BYTES}-byte limit"
        )));
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Unified archive listing
// ---------------------------------------------------------------------------

/// List entries in an archive, detecting the format from the filename extension.
///
/// Supported extensions:
/// - `.tar` — parse as TAR directly
/// - `.gz` — decompress; if the result is a valid TAR, list TAR entries,
///   otherwise return a single "(decompressed content)" entry
/// - `.tgz`, `.tar.gz` — decompress then parse as TAR
pub fn list_archive(data: &[u8], filename: &str) -> Result<Vec<ArchiveEntry>, CoreError> {
    let lower = filename.to_lowercase();

    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let decompressed = decompress_gzip(data)?;
        list_tar_entries(&decompressed)
    } else if lower.ends_with(".gz") {
        let decompressed = decompress_gzip(data)?;
        // Heuristic: if decompressed data looks like a TAR, parse it
        if decompressed.len() >= TAR_BLOCK_SIZE && decompressed[0] != 0 {
            match list_tar_entries(&decompressed) {
                Ok(entries) if !entries.is_empty() => Ok(entries),
                _ => Ok(vec![ArchiveEntry {
                    name: "(decompressed content)".to_string(),
                    size: decompressed.len() as u64,
                    is_directory: false,
                }]),
            }
        } else {
            Ok(vec![ArchiveEntry {
                name: "(decompressed content)".to_string(),
                size: decompressed.len() as u64,
                is_directory: false,
            }])
        }
    } else if lower.ends_with(".tar") {
        list_tar_entries(data)
    } else {
        Err(CoreError::InvalidInput(format!(
            "unsupported archive format: {filename}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Build a minimal TAR archive in memory with the given entries.
    /// Each entry is (name, content, is_directory).
    fn build_tar(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut buf = Vec::new();

        for &(name, content, is_dir) in entries {
            let mut header = [0u8; 512];

            // Name field (offset 0, 100 bytes)
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(100);
            header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            // Size field (offset 124, 12 bytes) — octal, null-terminated
            let size = if is_dir { 0 } else { content.len() };
            let size_str = format!("{:011o}\0", size);
            header[124..136].copy_from_slice(size_str.as_bytes());

            // Type flag (offset 156)
            header[156] = if is_dir { b'5' } else { b'0' };

            // Simplified checksum: sum of all header bytes (with checksum field as spaces)
            // Fill checksum field with spaces first
            header[148..156].fill(b' ');
            let checksum: u32 = header.iter().map(|&b| b as u32).sum();
            let checksum_str = format!("{:06o}\0 ", checksum);
            header[148..156].copy_from_slice(checksum_str.as_bytes());

            buf.extend_from_slice(&header);

            // Data blocks (padded to 512 bytes)
            if !is_dir && !content.is_empty() {
                buf.extend_from_slice(content);
                let remainder = content.len() % 512;
                if remainder != 0 {
                    buf.extend_from_slice(&vec![0u8; 512 - remainder]);
                }
            }
        }

        // End-of-archive: two 512-byte zero blocks
        buf.extend_from_slice(&[0u8; 1024]);
        buf
    }

    #[test]
    fn parse_tar_basic() {
        let tar = build_tar(&[
            ("hello.txt", b"Hello, World!", false),
            ("subdir/", b"", true),
            ("subdir/nested.rs", b"fn main() {}", false),
        ]);

        let entries = list_tar_entries(&tar).unwrap();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].size, 13);
        assert!(!entries[0].is_directory);

        assert_eq!(entries[1].name, "subdir");
        assert_eq!(entries[1].size, 0);
        assert!(entries[1].is_directory);

        assert_eq!(entries[2].name, "subdir/nested.rs");
        assert_eq!(entries[2].size, 12);
        assert!(!entries[2].is_directory);
    }

    #[test]
    fn parse_tar_empty_archive() {
        // Just two zero blocks = empty archive
        let tar = vec![0u8; 1024];
        let entries = list_tar_entries(&tar).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_tar_ignores_dot_entries() {
        let tar = build_tar(&[
            ("./", b"", true),
            (".", b"", true),
            ("real.txt", b"data", false),
        ]);
        let entries = list_tar_entries(&tar).unwrap();
        // Only "real.txt" should remain
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "real.txt");
    }

    #[test]
    fn gzip_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn gzip_invalid_data() {
        let result = decompress_gzip(b"not gzip data");
        assert!(result.is_err());
    }

    #[test]
    fn list_archive_tar() {
        let tar = build_tar(&[("file.rs", b"fn main() {}", false)]);
        let entries = list_archive(&tar, "archive.tar").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "file.rs");
    }

    #[test]
    fn list_archive_tgz() {
        let tar = build_tar(&[
            ("README.md", b"# Hello", false),
            ("src/", b"", true),
        ]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).unwrap();
        let compressed = encoder.finish().unwrap();

        let entries = list_archive(&compressed, "archive.tgz").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "README.md");
        assert!(entries[1].is_directory);
    }

    #[test]
    fn list_archive_tar_gz() {
        let tar = build_tar(&[("main.rs", b"fn main() {}", false)]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).unwrap();
        let compressed = encoder.finish().unwrap();

        let entries = list_archive(&compressed, "code.tar.gz").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "main.rs");
    }

    #[test]
    fn list_archive_plain_gz() {
        let original = b"just some text, not a tar";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let entries = list_archive(&compressed, "data.gz").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "(decompressed content)");
        assert_eq!(entries[0].size, original.len() as u64);
    }

    #[test]
    fn list_archive_unsupported_format() {
        let result = list_archive(b"data", "file.rar");
        assert!(result.is_err());
    }
}
