//! A gzip stream (RFC 1952), read sans-I/O: one or more members, each a
//! header, a raw deflate body and a CRC-32 + ISIZE trailer that must match.
//!
//! The stream reads compressed bytes from the source in windows of at most
//! [`PULL_AHEAD_BYTES`]; a miss leaves its state untouched, so the caller
//! retries the same call after the driver answers.

use super::inflate::Inflater;
use super::limits::PULL_AHEAD_BYTES;
use super::source::{ByteRange, ByteSource, Miss, read_exact_at};

/// The longest file name or comment field accepted in a gzip header.
const MAX_HEADER_FIELD: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GzStep {
    Data(Vec<u8>),
    /// Every member ended and its trailer matched.
    End,
    Miss(Miss),
    /// A bad header, a corrupt deflate body or a trailer that does not
    /// match its member.
    Corrupt,
}

enum State {
    Header,
    Body,
    Trailer,
    /// After a trailer: another member, or the end.
    Between,
    Done,
}

pub(crate) struct GzipStream {
    /// Compressed bytes `[buf_start, buf_start + buf.len())`, consumed up
    /// to `buf_pos`.
    buf: Vec<u8>,
    buf_start: u64,
    buf_pos: usize,
    state: State,
    inflater: Inflater,
    crc: flate2::Crc,
    member_out: u64,
    total_out: u64,
    first_header: Option<GzHeaderInfo>,
}

/// What the first member's header says.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GzHeaderInfo {
    pub name: Option<Vec<u8>>,
    /// Seconds since the epoch; 0 when the header has none.
    pub mtime: u32,
}

impl GzipStream {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            buf_start: 0,
            buf_pos: 0,
            state: State::Header,
            inflater: Inflater::new(),
            crc: flate2::Crc::new(),
            member_out: 0,
            total_out: 0,
            first_header: None,
        }
    }

    /// Compressed bytes consumed so far.
    pub(crate) fn total_in(&self) -> u64 {
        self.buf_start + self.buf_pos as u64
    }

    /// Decompressed bytes produced so far.
    pub(crate) fn total_out(&self) -> u64 {
        self.total_out
    }

    pub(crate) fn header(&self) -> Option<&GzHeaderInfo> {
        self.first_header.as_ref()
    }

    fn unread(&self) -> &[u8] {
        &self.buf[self.buf_pos..]
    }

    fn consume(&mut self, n: usize) {
        self.buf_pos += n;
    }

    /// Append the next window of compressed bytes. `Ok(false)` at the end
    /// of the file.
    fn fill_more<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, Miss> {
        let end = self.buf_start + self.buf.len() as u64;
        if end >= source.len() {
            return Ok(false);
        }
        let want_end = end.saturating_add(PULL_AHEAD_BYTES).min(source.len());
        let bytes = read_exact_at(source, ByteRange::new(end, want_end))?;
        if self.buf_pos > 0 {
            self.buf.drain(..self.buf_pos);
            self.buf_start += self.buf_pos as u64;
            self.buf_pos = 0;
        }
        self.buf.extend_from_slice(&bytes);
        source.release_before(self.buf_start);
        Ok(true)
    }

    /// The next piece of decompressed output, at most `max_out` bytes.
    pub(crate) fn next<S: ByteSource + ?Sized>(&mut self, source: &mut S, max_out: usize) -> GzStep {
        loop {
            match self.state {
                State::Done => return GzStep::End,
                State::Header => match parse_header(self.unread()) {
                    Header::Complete { len, info } => {
                        self.consume(len);
                        if self.first_header.is_none() {
                            self.first_header = Some(info);
                        }
                        self.inflater = Inflater::new();
                        self.crc = flate2::Crc::new();
                        self.member_out = 0;
                        self.state = State::Body;
                    }
                    Header::Incomplete => match self.fill_more(source) {
                        Ok(true) => {}
                        Ok(false) => return GzStep::Miss(Miss::Truncated),
                        Err(miss) => return GzStep::Miss(miss),
                    },
                    Header::Invalid => return GzStep::Corrupt,
                },
                State::Body => {
                    let mut out = Vec::new();
                    let input = &self.buf[self.buf_pos..];
                    let Ok(pushed) = self.inflater.push(input, &mut out, max_out.max(1)) else {
                        return GzStep::Corrupt;
                    };
                    self.consume(pushed.consumed);
                    self.crc.update(&out);
                    self.member_out += pushed.produced as u64;
                    self.total_out += pushed.produced as u64;
                    if pushed.stream_end {
                        self.state = State::Trailer;
                    }
                    if !out.is_empty() {
                        return GzStep::Data(out);
                    }
                    if pushed.stream_end || pushed.consumed > 0 {
                        continue;
                    }
                    // No progress: the decoder needs more input.
                    match self.fill_more(source) {
                        Ok(true) => {}
                        Ok(false) => return GzStep::Miss(Miss::Truncated),
                        Err(miss) => return GzStep::Miss(miss),
                    }
                }
                State::Trailer => {
                    if self.unread().len() < 8 {
                        match self.fill_more(source) {
                            Ok(true) => continue,
                            Ok(false) => return GzStep::Miss(Miss::Truncated),
                            Err(miss) => return GzStep::Miss(miss),
                        }
                    }
                    let t = &self.buf[self.buf_pos..self.buf_pos + 8];
                    let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
                    let isize = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
                    if crc != self.crc.sum() || isize != self.member_out as u32 {
                        return GzStep::Corrupt;
                    }
                    self.consume(8);
                    self.state = State::Between;
                }
                State::Between => {
                    if self.unread().len() < 2 {
                        match self.fill_more(source) {
                            Ok(true) => continue,
                            Ok(false) => {
                                self.state = State::Done;
                                continue;
                            }
                            Err(miss) => return GzStep::Miss(miss),
                        }
                    }
                    // Another member, or trailing bytes that are not one
                    // (padding, garbage): gzip ignores those, and so does
                    // core, because every member's own check has passed.
                    self.state = if self.unread().starts_with(&[0x1F, 0x8B]) {
                        State::Header
                    } else {
                        State::Done
                    };
                }
            }
        }
    }
}

enum Header {
    Complete { len: usize, info: GzHeaderInfo },
    Incomplete,
    Invalid,
}

fn parse_header(b: &[u8]) -> Header {
    const FHCRC: u8 = 0x02;
    const FEXTRA: u8 = 0x04;
    const FNAME: u8 = 0x08;
    const FCOMMENT: u8 = 0x10;
    if b.len() < 10 {
        return if b.is_empty() || b.starts_with(&[0x1F, 0x8B][..b.len().min(2)]) {
            Header::Incomplete
        } else {
            Header::Invalid
        };
    }
    if b[0] != 0x1F || b[1] != 0x8B || b[2] != 0x08 || b[3] & 0xE0 != 0 {
        return Header::Invalid;
    }
    let flags = b[3];
    let mtime = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let mut pos = 10usize;
    if flags & FEXTRA != 0 {
        let Some(x) = b.get(pos..pos + 2) else {
            return Header::Incomplete;
        };
        pos += 2 + usize::from(u16::from_le_bytes([x[0], x[1]]));
        if b.len() < pos {
            return Header::Incomplete;
        }
    }
    let mut name = None;
    for (flag, keep) in [(FNAME, true), (FCOMMENT, false)] {
        if flags & flag == 0 {
            continue;
        }
        let rest = &b[pos..];
        match rest.iter().position(|&c| c == 0) {
            Some(end) if end <= MAX_HEADER_FIELD => {
                if keep {
                    name = Some(rest[..end].to_vec());
                }
                pos += end + 1;
            }
            Some(_) => return Header::Invalid,
            None if rest.len() > MAX_HEADER_FIELD => return Header::Invalid,
            None => return Header::Incomplete,
        }
    }
    if flags & FHCRC != 0 {
        pos += 2;
        if b.len() < pos {
            return Header::Incomplete;
        }
    }
    Header::Complete {
        len: pos,
        info: GzHeaderInfo { name, mtime },
    }
}
