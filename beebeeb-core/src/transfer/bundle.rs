//! Multi-file bundle codec used inside a single transfer blob.
//!
//! Wire format (all integers little-endian):
//!
//! ```text
//! [u32 file_count]
//! repeat file_count times:
//!     [u32 name_len][name_bytes (UTF-8)]
//!     [u64 content_len][content_bytes]
//! ```
//!
//! The bundle is meant to live *inside* the AES-256-GCM ciphertext, so all
//! fields (names included) are encrypted on the wire. There are no magic
//! bytes — the wrapping cipher provides authentication.

use crate::CoreError;

const U32_LEN: usize = 4;
const U64_LEN: usize = 8;

/// Concatenate `(name, content)` pairs into a single self-describing buffer.
pub fn bundle_files(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let count: u32 = files.len().try_into().expect("file count fits in u32");

    let body_len: usize = files
        .iter()
        .map(|(name, content)| U32_LEN + name.len() + U64_LEN + content.len())
        .sum();
    let mut out = Vec::with_capacity(U32_LEN + body_len);

    out.extend_from_slice(&count.to_le_bytes());
    for (name, content) in files {
        let name_len: u32 = name.len().try_into().expect("name length fits in u32");
        let content_len: u64 = content.len() as u64;
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&content_len.to_le_bytes());
        out.extend_from_slice(content);
    }
    out
}

/// Parse a buffer produced by [`bundle_files`] back into `(name, content)` pairs.
pub fn unbundle_files(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, CoreError> {
    let mut cursor = 0usize;

    let count = read_u32(data, &mut cursor)? as usize;
    // Cap the up-front allocation to a sane bound so a corrupt header can't OOM us.
    // Each entry needs at least 4 + 8 = 12 bytes of header, so capacity can't exceed
    // (data.len() - 4) / 12.
    let cap = count.min(data.len().saturating_sub(U32_LEN) / (U32_LEN + U64_LEN));
    let mut files = Vec::with_capacity(cap);

    for _ in 0..count {
        let name_len = read_u32(data, &mut cursor)? as usize;
        let name_bytes = read_slice(data, &mut cursor, name_len)?;
        let name = String::from_utf8(name_bytes.to_vec())
            .map_err(|_| CoreError::InvalidInput("bundle: file name is not valid UTF-8".into()))?;

        let content_len = read_u64(data, &mut cursor)? as usize;
        let content = read_slice(data, &mut cursor, content_len)?.to_vec();

        files.push((name, content));
    }

    if cursor != data.len() {
        return Err(CoreError::InvalidInput(format!(
            "bundle: {} trailing bytes",
            data.len() - cursor
        )));
    }
    Ok(files)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32, CoreError> {
    let bytes: [u8; U32_LEN] = read_slice(data, cursor, U32_LEN)?
        .try_into()
        .expect("read_slice returned the requested length");
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64, CoreError> {
    let bytes: [u8; U64_LEN] = read_slice(data, cursor, U64_LEN)?
        .try_into()
        .expect("read_slice returned the requested length");
    Ok(u64::from_le_bytes(bytes))
}

fn read_slice<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], CoreError> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| CoreError::InvalidInput("bundle: length overflow".into()))?;
    if end > data.len() {
        return Err(CoreError::InvalidInput(format!(
            "bundle: truncated (need {end} bytes, have {})",
            data.len()
        )));
    }
    let slice = &data[*cursor..end];
    *cursor = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_three_files() {
        let files = vec![
            ("notes.txt".to_string(), b"hello, world".to_vec()),
            ("photo.jpg".to_string(), vec![0xFFu8; 4096]),
            ("song.mp3".to_string(), vec![0xABu8; 16]),
        ];
        let buf = bundle_files(&files);
        let recovered = unbundle_files(&buf).unwrap();
        assert_eq!(recovered, files);
    }

    #[test]
    fn empty_file_roundtrip() {
        let files = vec![("empty.bin".to_string(), Vec::new())];
        let buf = bundle_files(&files);
        let recovered = unbundle_files(&buf).unwrap();
        assert_eq!(recovered, files);
    }

    #[test]
    fn empty_bundle_roundtrip() {
        let files: Vec<(String, Vec<u8>)> = Vec::new();
        let buf = bundle_files(&files);
        assert_eq!(buf.len(), U32_LEN);
        let recovered = unbundle_files(&buf).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn unicode_filename_roundtrip() {
        let files = vec![("café-résumé.pdf".to_string(), b"pdf-bytes".to_vec())];
        let buf = bundle_files(&files);
        let recovered = unbundle_files(&buf).unwrap();
        assert_eq!(recovered, files);
    }

    #[test]
    fn truncated_bundle_returns_error() {
        let files = vec![("x".to_string(), vec![1, 2, 3])];
        let buf = bundle_files(&files);
        assert!(unbundle_files(&buf[..buf.len() - 1]).is_err());
    }

    #[test]
    fn trailing_bytes_return_error() {
        let files = vec![("x".to_string(), vec![1, 2, 3])];
        let mut buf = bundle_files(&files);
        buf.push(0xAB);
        assert!(unbundle_files(&buf).is_err());
    }

    #[test]
    fn invalid_utf8_filename_returns_error() {
        // count=1, name_len=2, name=[0xFF, 0xFE] (invalid UTF-8), content_len=0
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&[0xFF, 0xFE]);
        buf.extend_from_slice(&0u64.to_le_bytes());
        assert!(unbundle_files(&buf).is_err());
    }

    #[test]
    fn header_with_huge_count_does_not_oom() {
        // count = u32::MAX but no body — should fail fast on the first entry read,
        // not allocate a giant Vec.
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(unbundle_files(&buf).is_err());
    }
}
