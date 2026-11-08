//! Where the reader's bytes come from (spec §5.1, A1).
//!
//! The reader never does I/O: it reads through a [`ByteSource`]. A native
//! source blocks and never answers [`SourceError::Pending`]; the web driver
//! uses [`SuppliedBytes`], which answers `Pending` for a byte it does not
//! hold, and the session turns that into a `NeedBytes` demand. Both run the
//! same reader code.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use super::model::ArchiveRefusal;

/// A half-open byte range `[start, end)` of the archive file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// Why a read did not return bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// The source does not hold these bytes yet; the driver must supply
    /// them. Native sources never answer this.
    Pending(ByteRange),
    /// The source failed (a disk or network error).
    Io(String),
}

/// Random access to the archive file's bytes.
pub trait ByteSource {
    /// The archive file's length.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read up to `buf.len()` bytes at `offset`; a short read is allowed.
    /// `Ok(0)` only at or past the end of the file.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError>;

    /// The reader no longer needs any byte before `offset`. A source that
    /// holds bytes in memory may drop them.
    fn release_before(&mut self, _offset: u64) {}
}

impl<S: ByteSource + ?Sized> ByteSource for &mut S {
    fn len(&self) -> u64 {
        (**self).len()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        (**self).read_at(offset, buf)
    }

    fn release_before(&mut self, offset: u64) {
        (**self).release_before(offset)
    }
}

/// A blocking source over anything readable and seekable: a local file
/// (desktop, the CLI's cache) or an in-memory cursor.
pub struct ReadSeekSource<R: Read + Seek> {
    inner: R,
    len: u64,
}

impl<R: Read + Seek> ReadSeekSource<R> {
    pub fn new(mut inner: R) -> std::io::Result<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        Ok(Self { inner, len })
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> ByteSource for ReadSeekSource<R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(usize::try_from(self.len - offset).unwrap_or(usize::MAX));
        self.inner
            .seek(SeekFrom::Start(offset))
            .map_err(|e| SourceError::Io(e.to_string()))?;
        self.inner
            .read(&mut buf[..want])
            .map_err(|e| SourceError::Io(e.to_string()))
    }
}

/// The push driver's source: it holds only what the driver supplied.
///
/// Supplied ranges are kept disjoint. Bytes supplied twice must be equal (a
/// file that changes between two reads is damaged). When more than
/// `max_held_bytes` are held, the lowest ranges other than the one just
/// supplied are dropped; the reader asks again for anything it still needs.
pub struct SuppliedBytes {
    len: u64,
    max_held_bytes: u64,
    held: BTreeMap<u64, Vec<u8>>,
    held_bytes: u64,
}

impl SuppliedBytes {
    pub fn new(len: u64, max_held_bytes: u64) -> Self {
        Self {
            len,
            max_held_bytes,
            held: BTreeMap::new(),
            held_bytes: 0,
        }
    }

    /// Bytes held now.
    pub fn held_bytes(&self) -> u64 {
        self.held_bytes
    }

    /// Hand the reader the bytes at `offset`. Bytes past the end of the
    /// file, or bytes that differ from ones supplied before, refuse the
    /// archive as damaged.
    pub fn supply(&mut self, offset: u64, bytes: Vec<u8>) -> Result<(), ArchiveRefusal> {
        let end = offset.checked_add(bytes.len() as u64).ok_or(ArchiveRefusal::Damaged)?;
        if end > self.len {
            return Err(ArchiveRefusal::Damaged);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // Compare every overlap first, so a refused supply changes nothing.
        let overlapping: Vec<(u64, u64)> = self
            .held
            .range(..end)
            .map(|(start, seg)| (*start, *start + seg.len() as u64))
            .filter(|&(_, seg_end)| seg_end > offset)
            .collect();
        for &(start, seg_end) in &overlapping {
            let seg = &self.held[&start];
            let lo = start.max(offset);
            let hi = seg_end.min(end);
            let held_part = &seg[(lo - start) as usize..(hi - start) as usize];
            let new_part = &bytes[(lo - offset) as usize..(hi - offset) as usize];
            if held_part != new_part {
                return Err(ArchiveRefusal::Damaged);
            }
        }
        // Insert only the parts not held yet.
        let mut cursor = offset;
        let mut spans: Vec<(u64, u64)> = overlapping;
        spans.sort_unstable();
        for (start, seg_end) in spans.into_iter().chain(std::iter::once((end, end))) {
            if start > cursor {
                let part = bytes[(cursor - offset) as usize..(start.min(end) - offset) as usize].to_vec();
                self.held_bytes += part.len() as u64;
                self.held.insert(cursor, part);
            }
            cursor = cursor.max(seg_end);
        }
        self.evict_except(offset, end);
        Ok(())
    }

    fn evict_except(&mut self, keep_start: u64, keep_end: u64) {
        while self.held_bytes > self.max_held_bytes {
            let victim = self
                .held
                .iter()
                .map(|(start, seg)| (*start, *start + seg.len() as u64))
                .find(|&(start, seg_end)| seg_end <= keep_start || start >= keep_end);
            let Some((start, _)) = victim else {
                break;
            };
            if let Some(seg) = self.held.remove(&start) {
                self.held_bytes -= seg.len() as u64;
            }
        }
    }
}

impl ByteSource for SuppliedBytes {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        if let Some((start, seg)) = self.held.range(..=offset).next_back() {
            let seg_end = *start + seg.len() as u64;
            if offset < seg_end {
                let from = (offset - start) as usize;
                let n = buf.len().min(seg.len() - from);
                buf[..n].copy_from_slice(&seg[from..from + n]);
                return Ok(n);
            }
        }
        let end = offset.saturating_add(buf.len() as u64).min(self.len);
        Err(SourceError::Pending(ByteRange::new(offset, end)))
    }

    fn release_before(&mut self, offset: u64) {
        let starts: Vec<u64> = self.held.range(..offset).map(|(start, _)| *start).collect();
        for start in starts {
            let Some(seg) = self.held.remove(&start) else {
                continue;
            };
            self.held_bytes -= seg.len() as u64;
            let seg_end = start + seg.len() as u64;
            if seg_end > offset {
                let kept = seg[(offset - start) as usize..].to_vec();
                self.held_bytes += kept.len() as u64;
                self.held.insert(offset, kept);
            }
        }
    }
}

/// Why the reader could not get the bytes it needs right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Miss {
    /// Ask the driver for these bytes, then step again.
    Need(ByteRange),
    /// The bytes lie past the end of the file.
    Truncated,
    /// The source failed.
    Io(String),
}

/// Read exactly `range`, or say what is missing. Nothing is consumed on a
/// miss, so the caller can retry the same read after the driver answers.
pub(crate) fn read_exact_at<S: ByteSource + ?Sized>(source: &mut S, range: ByteRange) -> Result<Vec<u8>, Miss> {
    if range.end > source.len() {
        return Err(Miss::Truncated);
    }
    let len = usize::try_from(range.len()).map_err(|_| Miss::Truncated)?;
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        let at = range.start + filled as u64;
        match source.read_at(at, &mut buf[filled..]) {
            Ok(0) => return Err(Miss::Truncated),
            Ok(n) => filled += n.min(len - filled),
            Err(SourceError::Pending(_)) => return Err(Miss::Need(ByteRange::new(at, range.end))),
            Err(SourceError::Io(e)) => return Err(Miss::Io(e)),
        }
    }
    Ok(buf)
}
