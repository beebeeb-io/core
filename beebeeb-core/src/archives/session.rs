//! One archive, opened: detection, then the listing, then entry readers.
//!
//! The session is a step machine. The driver calls [`ArchiveSession::step`]
//! and answers each [`SessionStep::NeedBytes`] by supplying the range to
//! its source (a native source never asks), until the session says
//! `Listed` or `Refused`.

use super::detect::{ArchiveFormat, Detection, detect, detect_gzip_inner};
use super::limits::{DETECT_HEAD_BYTES, PIECE_BYTES, ZIP_TAIL_WINDOW};
use super::listing::{ListingBuilder, Locator};
use super::model::{ArchiveEntry, ArchiveListing, ArchiveRefusal, ArchiveTime, EntryCipher, EntryKind, SkipReason};
use super::names::{RawName, decode_name, display_name, entry_path};
use super::password::ArchivePassword;
use super::platform::ArchivePlatform;
use super::source::{ByteRange, ByteSource, read_exact_at};
use super::tar::{DataEvent, GzInput, Halt, RandomInput, TarEvent, TarHeader, TarInput, TarWalker};

/// What the session needs or says next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStep {
    /// Supply these bytes to the source, then step again.
    NeedBytes(ByteRange),
    /// The listing is ready: [`ArchiveSession::listing`].
    Listed,
    Refused(ArchiveRefusal),
    /// The source failed (a disk or network error), not the archive.
    Io(String),
}

enum Phase {
    Head,
    Tail { head: Vec<u8> },
    TarList(TarWalker<RandomInput>),
    GzDetect(GzInput),
    TgzList(TarWalker<GzInput>),
    GzList(GzInput),
    ZipPending,
    Listed,
    Refused(ArchiveRefusal),
}

pub struct ArchiveSession<S: ByteSource> {
    source: S,
    platform: ArchivePlatform,
    phase: Phase,
    builder: ListingBuilder,
    listing: Option<ArchiveListing>,
    locators: Vec<Locator>,
}

impl<S: ByteSource> ArchiveSession<S> {
    pub fn open(source: S, platform: ArchivePlatform) -> Self {
        Self {
            source,
            platform,
            phase: Phase::Head,
            builder: ListingBuilder::default(),
            listing: None,
            locators: Vec::new(),
        }
    }

    pub fn platform(&self) -> ArchivePlatform {
        self.platform
    }

    pub fn listing(&self) -> Option<&ArchiveListing> {
        self.listing.as_ref()
    }

    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// Advance detection and listing as far as the source allows.
    pub fn step(&mut self) -> SessionStep {
        loop {
            let outcome = match &mut self.phase {
                Phase::Listed => return SessionStep::Listed,
                Phase::Refused(refusal) => return SessionStep::Refused(*refusal),
                Phase::Head => self.step_head(),
                Phase::Tail { .. } => self.step_tail(),
                Phase::TarList(_) => self.step_tar_list(),
                Phase::GzDetect(_) => self.step_gz_detect(),
                Phase::TgzList(_) => self.step_tgz_list(),
                Phase::GzList(_) => self.step_gz_list(),
                Phase::ZipPending => Err(Halt::Refused(ArchiveRefusal::Damaged)),
            };
            match outcome {
                Ok(()) => continue,
                Err(Halt::Need(range)) => return SessionStep::NeedBytes(range),
                Err(Halt::Io(e)) => return SessionStep::Io(e),
                Err(Halt::Refused(refusal)) => {
                    self.phase = Phase::Refused(refusal);
                    self.builder = ListingBuilder::default();
                }
                Err(Halt::Limit) => {
                    self.phase = Phase::Refused(ArchiveRefusal::Damaged);
                }
            }
        }
    }

    fn step_head(&mut self) -> Result<(), Halt> {
        let len = self.source.len();
        if len == 0 {
            return Err(Halt::Refused(ArchiveRefusal::NotAnArchive));
        }
        let head = read_exact_at(&mut self.source, ByteRange::new(0, len.min(DETECT_HEAD_BYTES)))?;
        if head.starts_with(b"MZ") {
            self.phase = Phase::Tail { head };
            return Ok(());
        }
        self.detected(detect(&head, &[], len))
    }

    fn step_tail(&mut self) -> Result<(), Halt> {
        let len = self.source.len();
        let tail = read_exact_at(
            &mut self.source,
            ByteRange::new(len.saturating_sub(ZIP_TAIL_WINDOW), len),
        )?;
        let Phase::Tail { head } = &self.phase else {
            return Ok(());
        };
        let detection = detect(head, &tail, len);
        self.detected(detection)
    }

    fn detected(&mut self, detection: Detection) -> Result<(), Halt> {
        self.phase = match detection {
            Detection::Archive(ArchiveFormat::Tar) => Phase::TarList(TarWalker::new(RandomInput { pos: 0 })),
            Detection::Archive(ArchiveFormat::Zip) => Phase::ZipPending,
            Detection::Archive(_) | Detection::GzipNeedsInflatedHead => Phase::GzDetect(GzInput::new(None)),
            Detection::Foreign(format) => return Err(Halt::Refused(ArchiveRefusal::Foreign(format))),
            Detection::SelfExtracting => return Err(Halt::Refused(ArchiveRefusal::SelfExtracting)),
            Detection::NotAnArchive => return Err(Halt::Refused(ArchiveRefusal::NotAnArchive)),
        };
        Ok(())
    }

    fn step_tar_list(&mut self) -> Result<(), Halt> {
        let Phase::TarList(walker) = &mut self.phase else {
            return Ok(());
        };
        loop {
            match walker.next_entry(&mut self.source)? {
                TarEvent::Entry(header) => {
                    let (entry, locator) = tar_entry(&header);
                    self.builder.push(entry, locator).map_err(Halt::Refused)?;
                }
                TarEvent::End => return self.finish_listing(ArchiveFormat::Tar, true),
            }
        }
    }

    fn step_gz_detect(&mut self) -> Result<(), Halt> {
        let scan = self.platform.preview_scan_bytes();
        let Phase::GzDetect(input) = &mut self.phase else {
            return Ok(());
        };
        input.fill_to(&mut self.source, 512)?;
        let format = detect_gzip_inner(input.peek(512));
        let mut input = std::mem::replace(input, GzInput::new(None));
        input.limit = Some(scan);
        self.phase = match format {
            ArchiveFormat::TarGzip => Phase::TgzList(TarWalker::new(input)),
            _ => Phase::GzList(input),
        };
        Ok(())
    }

    fn step_tgz_list(&mut self) -> Result<(), Halt> {
        let Phase::TgzList(walker) = &mut self.phase else {
            return Ok(());
        };
        loop {
            match walker.next_entry(&mut self.source) {
                Ok(TarEvent::Entry(header)) => {
                    let (entry, locator) = tar_entry(&header);
                    self.builder.push(entry, locator).map_err(Halt::Refused)?;
                }
                Ok(TarEvent::End) => return self.finish_listing(ArchiveFormat::TarGzip, true),
                Err(Halt::Limit) => return self.finish_listing(ArchiveFormat::TarGzip, false),
                Err(halt) => return Err(halt),
            }
        }
    }

    fn step_gz_list(&mut self) -> Result<(), Halt> {
        let Phase::GzList(input) = &mut self.phase else {
            return Ok(());
        };
        let complete = loop {
            match input.skip(&mut self.source, u64::MAX) {
                Ok(_) => {}
                Err(Halt::Limit) => break false,
                Err(Halt::Refused(ArchiveRefusal::Truncated)) if input.ended() => break true,
                Err(halt) => return Err(halt),
            }
        };
        let size = input.pos();
        let compressed = self.source.len();
        let header = input.gz.header().cloned().unwrap_or_default();
        let name = header.name.as_deref().map(|raw| {
            let decoded = decode_name(RawName::Tar {
                pax_path: None,
                gnu_long: Some(raw),
                prefix: b"",
                name: b"",
            });
            decoded.rsplit(['/', '\\']).next().unwrap_or_default().to_string()
        });
        let display = name.as_deref().map(display_name).unwrap_or_default();
        let entry = ArchiveEntry {
            index: 0,
            path: name.as_deref().and_then(|n| entry_path(n).ok()),
            display_path: display,
            kind: EntryKind::File,
            size,
            compressed_size: compressed,
            cipher: EntryCipher::None,
            modified: (header.mtime != 0).then(|| ArchiveTime::Utc {
                unix_ms: i64::from(header.mtime) * 1000,
            }),
            skip: None,
        };
        self.builder.push(entry, Locator::Gzip).map_err(Halt::Refused)?;
        self.finish_listing(ArchiveFormat::Gzip, complete)
    }

    fn finish_listing(&mut self, format: ArchiveFormat, complete: bool) -> Result<(), Halt> {
        let builder = std::mem::take(&mut self.builder);
        let (listing, locators) = builder.finish(format, complete);
        self.listing = Some(listing);
        self.locators = locators;
        self.phase = Phase::Listed;
        Ok(())
    }

    /// A reader for one listed entry's plaintext. Its pieces are at most
    /// 64 KiB; it ends with `Verified` only after the entry's own check
    /// passed. Refused before the listing exists or for an index it lacks.
    pub fn entry_reader(
        &mut self,
        index: u32,
        password: Option<&ArchivePassword>,
    ) -> Result<EntryReader<'_, S>, ArchiveRefusal> {
        let _ = password;
        let decoder = self.decoder(index)?;
        Ok(EntryReader { session: self, decoder })
    }

    pub(crate) fn decoder(&self, index: u32) -> Result<EntryDecoder, ArchiveRefusal> {
        let listing = self.listing.as_ref().ok_or(ArchiveRefusal::Damaged)?;
        let locator = self.locators.get(index as usize).ok_or(ArchiveRefusal::Damaged)?;
        Ok(match (listing.format, locator) {
            (_, Locator::None) => EntryDecoder::Empty,
            (ArchiveFormat::Tar, Locator::Tar { data_offset, size, .. }) => EntryDecoder::TarPlain {
                pos: *data_offset,
                remaining: *size,
            },
            (ArchiveFormat::TarGzip, Locator::Tar { ordinal, .. }) => EntryDecoder::Tgz {
                walker: Box::new(TarWalker::new(GzInput::new(None))),
                ordinal: *ordinal,
                found: false,
            },
            (_, Locator::Gzip) => EntryDecoder::Gz {
                input: Box::new(GzInput::new(None)),
                max: self.platform.max_entry_bytes(),
            },
            _ => return Err(ArchiveRefusal::Damaged),
        })
    }
}

/// The listing entry for a tar header.
fn tar_entry(header: &TarHeader) -> (ArchiveEntry, Locator) {
    let (kind, type_skip) = match header.typeflag {
        b'0' | 0 | b'7' if header.name.ends_with('/') => (EntryKind::Folder, None),
        b'0' | 0 | b'7' => (EntryKind::File, None),
        b'5' | b'D' => (EntryKind::Folder, None),
        b'1' => (EntryKind::HardLink, Some(SkipReason::Link)),
        b'2' => (EntryKind::Symlink, Some(SkipReason::Link)),
        b'3' | b'4' | b'6' => (EntryKind::Device, Some(SkipReason::Device)),
        b'S' => (EntryKind::Other, Some(SkipReason::Unsupported("Sparse file".into()))),
        b'M' => (
            EntryKind::Other,
            Some(SkipReason::Unsupported("Part of a multi-volume archive".into())),
        ),
        _ => (
            EntryKind::Other,
            Some(SkipReason::Unsupported("Unknown entry type".into())),
        ),
    };
    let path = entry_path(&header.name);
    let skip = match &path {
        Err(reason) => Some(reason.clone()),
        Ok(_) => type_skip,
    };
    let locator = match kind {
        EntryKind::File if skip.is_none() => Locator::Tar {
            ordinal: header.ordinal,
            data_offset: header.data_offset,
            size: header.size,
        },
        _ => Locator::None,
    };
    let entry = ArchiveEntry {
        index: 0,
        display_path: display_name(&header.name),
        path: path.ok(),
        kind,
        size: if kind == EntryKind::Folder { 0 } else { header.size },
        compressed_size: header.size,
        cipher: EntryCipher::None,
        modified: header.mtime_ms.map(|unix_ms| ArchiveTime::Utc { unix_ms }),
        skip,
    };
    (entry, locator)
}

/// What an entry reader gives next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceStep {
    /// Plaintext, at most 64 KiB. Not yet verified: stage it, never
    /// publish it before `Verified`.
    Data(Vec<u8>),
    /// Supply these bytes to the source, then ask again.
    NeedBytes(ByteRange),
    /// Every byte was read and the entry's own check passed.
    Verified,
    /// The entry's check failed, or its bytes are damaged.
    Corrupt,
    /// The password is wrong (or missing for an encrypted entry).
    WrongPassword,
    /// The entry cannot be extracted after all (for example it expands
    /// past its declared size: `Bomb`).
    Skipped(SkipReason),
    /// The source failed.
    Io(String),
}

pub(crate) enum EntryDecoder {
    Empty,
    TarPlain {
        pos: u64,
        remaining: u64,
    },
    Tgz {
        walker: Box<TarWalker<GzInput>>,
        ordinal: u32,
        found: bool,
    },
    Gz {
        input: Box<GzInput>,
        max: u64,
    },
    Done,
}

impl EntryDecoder {
    pub(crate) fn next_piece<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> PieceStep {
        let step = match self {
            EntryDecoder::Done => return PieceStep::Verified,
            EntryDecoder::Empty => Ok(PieceStep::Verified),
            EntryDecoder::TarPlain { remaining: 0, .. } => Ok(PieceStep::Verified),
            EntryDecoder::TarPlain { pos, remaining } => {
                let mut input = RandomInput { pos: *pos };
                input
                    .piece(source, (*remaining).min(PIECE_BYTES as u64) as usize)
                    .map(|piece| {
                        *pos = input.pos;
                        *remaining -= piece.len() as u64;
                        PieceStep::Data(piece)
                    })
            }
            EntryDecoder::Tgz { walker, ordinal, found } => tgz_piece(walker, *ordinal, found, source),
            EntryDecoder::Gz { input, max } => match input.piece(source, PIECE_BYTES) {
                Ok(_) if input.pos() > *max => Ok(PieceStep::Skipped(SkipReason::TooLarge)),
                Ok(piece) => Ok(PieceStep::Data(piece)),
                Err(Halt::Refused(ArchiveRefusal::Truncated)) if input.ended() => Ok(PieceStep::Verified),
                Err(halt) => Err(halt),
            },
        };
        let step = match step {
            Ok(step) => step,
            Err(Halt::Need(range)) => return PieceStep::NeedBytes(range),
            Err(Halt::Io(e)) => return PieceStep::Io(e),
            Err(Halt::Refused(ArchiveRefusal::Bomb)) => PieceStep::Skipped(SkipReason::Bomb),
            Err(Halt::Refused(_) | Halt::Limit) => PieceStep::Corrupt,
        };
        if !matches!(step, PieceStep::Data(_)) {
            *self = EntryDecoder::Done;
        }
        step
    }
}

fn tgz_piece<S: ByteSource + ?Sized>(
    walker: &mut TarWalker<GzInput>,
    ordinal: u32,
    found: &mut bool,
    source: &mut S,
) -> Result<PieceStep, Halt> {
    while !*found {
        match walker.next_entry(source)? {
            TarEvent::Entry(header) if header.ordinal == ordinal => *found = true,
            TarEvent::Entry(_) => {}
            TarEvent::End => return Ok(PieceStep::Corrupt),
        }
    }
    Ok(match walker.next_data(source, PIECE_BYTES)? {
        DataEvent::Data(piece) => PieceStep::Data(piece),
        DataEvent::DataEnd => PieceStep::Verified,
    })
}

/// Reads one entry's plaintext; see [`ArchiveSession::entry_reader`].
pub struct EntryReader<'a, S: ByteSource> {
    session: &'a mut ArchiveSession<S>,
    decoder: EntryDecoder,
}

impl<S: ByteSource> EntryReader<'_, S> {
    pub fn next_piece(&mut self) -> PieceStep {
        self.decoder.next_piece(&mut self.session.source)
    }

    /// The source, to supply what `NeedBytes` asked for.
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.session.source
    }
}
