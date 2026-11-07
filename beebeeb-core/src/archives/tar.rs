//! Tar, read sans-I/O over either the archive's bytes (a plain `.tar`,
//! random access) or a gzip stream (`.tgz`, in order).
//!
//! The walker reads one header at a time. Over random access, skipping an
//! entry's data costs no read at all, so listing a 10 GB tar of large files
//! reads only the blocks that hold headers (spec §5.1). Every operation
//! either completes or leaves the walker as it was, so a miss is retried by
//! calling the same method again.

use super::detect::{is_tar_header, parse_octal};
use super::gzip::{GzStep, GzipStream};
use super::limits::{BOMB_RATIO, BOMB_RATIO_FLOOR_BYTES, MAX_TAR_META_BYTES, PIECE_BYTES};
use super::model::ArchiveRefusal;
use super::names::{RawName, decode_name};
use super::source::{ByteRange, ByteSource, Miss, read_exact_at};

const BLOCK: u64 = 512;

/// Why a reader stopped before it could answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Halt {
    /// Ask the driver for these bytes, then step again.
    Need(ByteRange),
    Io(String),
    Refused(ArchiveRefusal),
    /// A gzip stream passed the decompressed limit set on it.
    Limit,
}

impl From<Miss> for Halt {
    fn from(miss: Miss) -> Self {
        match miss {
            Miss::Need(range) => Halt::Need(range),
            Miss::Truncated => Halt::Refused(ArchiveRefusal::Truncated),
            Miss::Io(e) => Halt::Io(e),
        }
    }
}

/// The bytes a tar is read from.
pub(crate) trait TarInput {
    /// The tar stream position (the file offset, or the decompressed
    /// offset of a gzip stream).
    fn pos(&self) -> u64;
    /// Exactly `n` bytes, consumed only when they are all there.
    fn take<S: ByteSource + ?Sized>(&mut self, source: &mut S, n: usize) -> Result<Vec<u8>, Halt>;
    /// Skip up to `n` bytes; returns how many (at least 1 when `n > 0`).
    fn skip<S: ByteSource + ?Sized>(&mut self, source: &mut S, n: u64) -> Result<u64, Halt>;
    /// Up to `max` bytes, at least 1.
    fn piece<S: ByteSource + ?Sized>(&mut self, source: &mut S, max: usize) -> Result<Vec<u8>, Halt>;
    /// Whether the stream has no byte left.
    fn at_end<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, Halt>;
}

/// A plain tar: the archive's own bytes, at random.
pub(crate) struct RandomInput {
    pub pos: u64,
}

impl TarInput for RandomInput {
    fn pos(&self) -> u64 {
        self.pos
    }

    fn take<S: ByteSource + ?Sized>(&mut self, source: &mut S, n: usize) -> Result<Vec<u8>, Halt> {
        let end = self
            .pos
            .checked_add(n as u64)
            .ok_or(Halt::Refused(ArchiveRefusal::Damaged))?;
        let bytes = read_exact_at(source, ByteRange::new(self.pos, end))?;
        self.pos = end;
        source.release_before(self.pos);
        Ok(bytes)
    }

    fn skip<S: ByteSource + ?Sized>(&mut self, source: &mut S, n: u64) -> Result<u64, Halt> {
        let end = self.pos.checked_add(n).ok_or(Halt::Refused(ArchiveRefusal::Damaged))?;
        if end > source.len() {
            return Err(Halt::Refused(ArchiveRefusal::Truncated));
        }
        self.pos = end;
        Ok(n)
    }

    fn piece<S: ByteSource + ?Sized>(&mut self, source: &mut S, max: usize) -> Result<Vec<u8>, Halt> {
        let left = source.len().saturating_sub(self.pos);
        if left == 0 {
            return Err(Halt::Refused(ArchiveRefusal::Truncated));
        }
        let n = (max as u64).min(left) as usize;
        self.take(source, n)
    }

    fn at_end<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, Halt> {
        Ok(self.pos >= source.len())
    }
}

/// A tar inside gzip, decompressed in order. It also enforces the gzip
/// bomb rule (past 1 GiB of output, never more than 1,000:1) and an
/// optional decompressed limit (the preview scan).
pub(crate) struct GzInput {
    pub gz: GzipStream,
    out: Vec<u8>,
    out_pos: usize,
    pos: u64,
    ended: bool,
    pub limit: Option<u64>,
}

impl GzInput {
    pub(crate) fn new(limit: Option<u64>) -> Self {
        Self {
            gz: GzipStream::new(),
            out: Vec::new(),
            out_pos: 0,
            pos: 0,
            ended: false,
            limit,
        }
    }

    fn buffered(&self) -> usize {
        self.out.len() - self.out_pos
    }

    /// Pull one more piece into the buffer. `Ok(false)` at the end.
    fn pull<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, Halt> {
        if self.ended {
            return Ok(false);
        }
        if let Some(limit) = self.limit
            && self.pos + self.buffered() as u64 >= limit
        {
            return Err(Halt::Limit);
        }
        match self.gz.next(source, PIECE_BYTES) {
            GzStep::Data(data) => {
                let out = self.gz.total_out();
                if out > BOMB_RATIO_FLOOR_BYTES && out / BOMB_RATIO.max(1) > self.gz.total_in() {
                    return Err(Halt::Refused(ArchiveRefusal::Bomb));
                }
                if self.out_pos > 0 {
                    self.out.drain(..self.out_pos);
                    self.out_pos = 0;
                }
                self.out.extend_from_slice(&data);
                Ok(true)
            }
            GzStep::End => {
                self.ended = true;
                Ok(false)
            }
            GzStep::Miss(miss) => Err(miss.into()),
            GzStep::Corrupt => Err(Halt::Refused(ArchiveRefusal::Damaged)),
        }
    }

    /// Buffer at least `n` bytes, or everything left when the stream ends
    /// first. Returns how many are buffered.
    pub(crate) fn fill_to<S: ByteSource + ?Sized>(&mut self, source: &mut S, n: usize) -> Result<usize, Halt> {
        while self.buffered() < n {
            if !self.pull(source)? {
                break;
            }
        }
        Ok(self.buffered())
    }

    pub(crate) fn peek(&self, n: usize) -> &[u8] {
        &self.out[self.out_pos..self.out_pos + n.min(self.buffered())]
    }

    /// Whether the gzip stream ended (every member's trailer matched).
    pub(crate) fn ended(&self) -> bool {
        self.ended
    }
}

impl TarInput for GzInput {
    fn pos(&self) -> u64 {
        self.pos
    }

    fn take<S: ByteSource + ?Sized>(&mut self, source: &mut S, n: usize) -> Result<Vec<u8>, Halt> {
        if self.fill_to(source, n)? < n {
            return Err(Halt::Refused(ArchiveRefusal::Truncated));
        }
        let bytes = self.out[self.out_pos..self.out_pos + n].to_vec();
        self.out_pos += n;
        self.pos += n as u64;
        Ok(bytes)
    }

    fn skip<S: ByteSource + ?Sized>(&mut self, source: &mut S, n: u64) -> Result<u64, Halt> {
        if n == 0 {
            return Ok(0);
        }
        if self.buffered() == 0 && !self.pull(source)? {
            return Err(Halt::Refused(ArchiveRefusal::Truncated));
        }
        let skipped = (self.buffered() as u64).min(n);
        self.out_pos += skipped as usize;
        self.pos += skipped;
        Ok(skipped)
    }

    fn piece<S: ByteSource + ?Sized>(&mut self, source: &mut S, max: usize) -> Result<Vec<u8>, Halt> {
        if self.buffered() == 0 && !self.pull(source)? {
            return Err(Halt::Refused(ArchiveRefusal::Truncated));
        }
        let n = self.buffered().min(max);
        let bytes = self.out[self.out_pos..self.out_pos + n].to_vec();
        self.out_pos += n;
        self.pos += n as u64;
        Ok(bytes)
    }

    fn at_end<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, Halt> {
        Ok(self.buffered() == 0 && !self.pull(source)?)
    }
}

/// One tar entry's header, with its pax and GNU metadata applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TarHeader {
    pub name: String,
    pub typeflag: u8,
    pub size: u64,
    /// Seconds since the epoch, with the pax fraction as milliseconds.
    pub mtime_ms: Option<i64>,
    /// The entry's ordinal among real entries (metadata headers excluded).
    pub ordinal: u32,
    pub data_offset: u64,
}

#[derive(Default)]
struct Pending {
    pax_path: Option<Vec<u8>>,
    pax_size: Option<u64>,
    pax_mtime_ms: Option<i64>,
    gnu_long: Option<Vec<u8>>,
}

enum State {
    Header,
    /// A metadata header was read; its `padded` body comes next.
    Meta {
        typeflag: u8,
        size: u64,
        padded: u64,
    },
    /// A GNU sparse header was read; extension blocks come next.
    SparseExt {
        block: Box<[u8; 512]>,
    },
    /// Inside an entry's data: `remaining` data bytes, then `pad`.
    Data {
        remaining: u64,
        pad: u64,
    },
    /// Skipping bytes before the next header.
    Skip {
        remaining: u64,
    },
    End,
}

/// What the walker found next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TarEvent {
    Entry(TarHeader),
    End,
}

/// What an entry's data gave next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DataEvent {
    Data(Vec<u8>),
    /// The entry's declared bytes are all read.
    DataEnd,
}

pub(crate) struct TarWalker<I: TarInput> {
    pub input: I,
    state: State,
    pending: Pending,
    ordinal: u32,
}

impl<I: TarInput> TarWalker<I> {
    pub(crate) fn new(input: I) -> Self {
        Self {
            input,
            state: State::Header,
            pending: Pending::default(),
            ordinal: 0,
        }
    }

    /// Real entries returned so far.
    pub(crate) fn ordinals(&self) -> u32 {
        self.ordinal
    }

    /// The next real entry, skipping whatever is left of the current one.
    pub(crate) fn next_entry<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<TarEvent, Halt> {
        loop {
            match self.state {
                State::End => return Ok(TarEvent::End),
                State::Data { remaining, pad } => {
                    self.state = State::Skip {
                        remaining: remaining + pad,
                    };
                }
                State::Skip { remaining: 0 } => self.state = State::Header,
                State::Skip { remaining } => {
                    let skipped = self.input.skip(source, remaining)?;
                    self.state = State::Skip {
                        remaining: remaining - skipped,
                    };
                }
                State::Header => {
                    if self.input.at_end(source)? {
                        // A tar that ends on a block boundary with no zero
                        // blocks is complete (some writers omit them).
                        self.state = State::End;
                        continue;
                    }
                    let block = self.input.take(source, BLOCK as usize)?;
                    if let Some(header) = self.header(&block)? {
                        return Ok(TarEvent::Entry(header));
                    }
                }
                State::Meta { typeflag, size, padded } => {
                    let data = self.input.take(source, padded as usize)?;
                    let data = &data[..size as usize];
                    match typeflag {
                        b'x' => self.absorb_pax(data, false)?,
                        b'g' => self.absorb_pax(data, true)?,
                        b'L' => self.pending.gnu_long = Some(data.to_vec()),
                        _ => {} // K: a long link target; links are never extracted.
                    }
                    self.state = State::Header;
                }
                State::SparseExt { .. } => {
                    let ext = self.input.take(source, BLOCK as usize)?;
                    if ext[504] == 0 {
                        let State::SparseExt { block } = std::mem::replace(&mut self.state, State::Header) else {
                            continue;
                        };
                        return self.entry(&block[..]).map(TarEvent::Entry);
                    }
                }
            }
        }
    }

    /// The next piece of the current entry's data.
    pub(crate) fn next_data<S: ByteSource + ?Sized>(&mut self, source: &mut S, max: usize) -> Result<DataEvent, Halt> {
        match self.state {
            State::Data { remaining: 0, pad } => {
                self.state = State::Skip { remaining: pad };
                Ok(DataEvent::DataEnd)
            }
            State::Data { remaining, pad } => {
                let piece = self.input.piece(source, (max as u64).min(remaining) as usize)?;
                self.state = State::Data {
                    remaining: remaining - piece.len() as u64,
                    pad,
                };
                Ok(DataEvent::Data(piece))
            }
            _ => Ok(DataEvent::DataEnd),
        }
    }

    /// Parse one header block (already consumed). Metadata headers move the
    /// walker to their body and give `None`; a real entry moves it into its
    /// data. Every multi-read step is its own state, so a miss never loses
    /// a block that was already read.
    fn header(&mut self, block: &[u8]) -> Result<Option<TarHeader>, Halt> {
        if block.iter().all(|&b| b == 0) {
            self.state = State::End;
            return Ok(None);
        }
        if !is_tar_header(block) {
            return Err(Halt::Refused(ArchiveRefusal::Damaged));
        }
        let typeflag = block[156];
        let size = parse_number(&block[124..136]).ok_or(Halt::Refused(ArchiveRefusal::Damaged))?;
        let padded = padded(size)?;
        match typeflag {
            b'x' | b'g' | b'L' | b'K' => {
                if size > MAX_TAR_META_BYTES {
                    return Err(Halt::Refused(ArchiveRefusal::Damaged));
                }
                self.state = State::Meta { typeflag, size, padded };
                Ok(None)
            }
            b'V' => {
                self.state = State::Skip { remaining: padded };
                Ok(None)
            }
            b'S' if block[482] != 0 => {
                let mut saved = Box::new([0u8; 512]);
                saved.copy_from_slice(&block[..512]);
                self.state = State::SparseExt { block: saved };
                Ok(None)
            }
            _ => self.entry(block).map(Some),
        }
    }

    /// A real entry's header: apply the pending metadata and move into its
    /// data.
    fn entry(&mut self, block: &[u8]) -> Result<TarHeader, Halt> {
        let pending = std::mem::take(&mut self.pending);
        let ustar = &block[257..263] == b"ustar\0";
        let prefix: &[u8] = if ustar { &block[345..500] } else { &[] };
        let name = decode_name(RawName::Tar {
            pax_path: pending.pax_path.as_deref(),
            gnu_long: pending.gnu_long.as_deref(),
            prefix,
            name: &block[..100],
        });
        let header_size = parse_number(&block[124..136]).ok_or(Halt::Refused(ArchiveRefusal::Damaged))?;
        let size = pending.pax_size.unwrap_or(header_size);
        let padded = padded(size)?;
        let header_mtime = parse_number(&block[136..148])
            .and_then(|s| i64::try_from(s).ok())
            .and_then(|s| s.checked_mul(1000));
        let header = TarHeader {
            name,
            typeflag: block[156],
            size,
            mtime_ms: pending.pax_mtime_ms.or(header_mtime),
            ordinal: self.ordinal,
            data_offset: self.input.pos(),
        };
        self.ordinal += 1;
        self.state = State::Data {
            remaining: size,
            pad: padded - size,
        };
        Ok(header)
    }

    fn absorb_pax(&mut self, data: &[u8], global: bool) -> Result<(), Halt> {
        for (key, value) in parse_pax(data).ok_or(Halt::Refused(ArchiveRefusal::Damaged))? {
            match (key, global) {
                (b"path", false) => self.pending.pax_path = Some(value.to_vec()),
                (b"size", false) => {
                    let size = std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or(Halt::Refused(ArchiveRefusal::Damaged))?;
                    self.pending.pax_size = Some(size);
                }
                (b"mtime", false) => self.pending.pax_mtime_ms = parse_pax_time(value),
                // Global records are checked for form; none of them names
                // or sizes an entry, so none is applied.
                _ => {}
            }
        }
        Ok(())
    }
}

fn padded(size: u64) -> Result<u64, Halt> {
    size.checked_add(BLOCK - 1)
        .map(|n| n / BLOCK * BLOCK)
        .ok_or(Halt::Refused(ArchiveRefusal::Damaged))
}

/// An octal field, or a GNU base-256 field (high bit set): big-endian
/// binary in the remaining bytes. `None` when it does not fit 64 bits.
pub(crate) fn parse_number(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        if field[0] & 0x40 != 0 {
            return None; // negative
        }
        let mut value: u64 = u64::from(field[0] & 0x3F);
        for &b in &field[1..] {
            value = value.checked_mul(256)?.checked_add(u64::from(b))?;
        }
        return Some(value);
    }
    if field.iter().all(|&b| b == 0 || b == b' ') {
        return Some(0);
    }
    parse_octal(field)
}

/// pax records: `"%d %s=%s\n"`, the length counting the whole record.
fn parse_pax(mut data: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let mut records = Vec::new();
    while !data.is_empty() {
        if data.iter().all(|&b| b == 0) {
            break;
        }
        let space = data.iter().position(|&b| b == b' ')?;
        let len: usize = std::str::from_utf8(&data[..space]).ok()?.parse().ok()?;
        if len <= space + 1 || len > data.len() || data[len - 1] != b'\n' {
            return None;
        }
        let record = &data[space + 1..len - 1];
        let eq = record.iter().position(|&b| b == b'=')?;
        records.push((&record[..eq], &record[eq + 1..]));
        data = &data[len..];
    }
    Some(records)
}

/// A pax time, `seconds[.fraction]`, as milliseconds.
fn parse_pax_time(value: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(value).ok()?;
    let (secs, frac) = text.split_once('.').unwrap_or((text, ""));
    let secs: i64 = secs.parse().ok()?;
    let millis: i64 = format!("{frac:0<3}").get(..3)?.parse().ok()?;
    secs.checked_mul(1000)?
        .checked_add(if secs < 0 { -millis } else { millis })
}
