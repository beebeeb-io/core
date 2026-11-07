//! Fixture builders and test sources shared by the reader tests.
//!
//! Every archive is built here, in memory; bombs are never committed.

#![allow(dead_code)]

use std::io::Write;

use beebeeb_core::archives::{
    ArchiveListing, ArchivePlatform, ArchiveRefusal, ArchiveSession, ByteRange, ByteSource, PieceStep, SessionStep,
    SourceError,
};

/// A blocking source over bytes: never answers `Pending`.
pub struct Blocking(pub Vec<u8>);

impl ByteSource for Blocking {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        let start = (offset as usize).min(self.0.len());
        let n = buf.len().min(self.0.len() - start);
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        Ok(n)
    }
}

/// A blocking source that records every byte range it returned.
pub struct Recording {
    pub bytes: Vec<u8>,
    pub reads: Vec<ByteRange>,
}

impl Recording {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            reads: Vec::new(),
        }
    }

    pub fn bytes_read(&self) -> u64 {
        self.reads.iter().map(ByteRange::len).sum()
    }
}

impl ByteSource for Recording {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        let start = (offset as usize).min(self.bytes.len());
        let n = buf.len().min(self.bytes.len() - start);
        buf[..n].copy_from_slice(&self.bytes[start..start + n]);
        self.reads.push(ByteRange::new(offset, offset + n as u64));
        Ok(n)
    }
}

/// A source that answers at random: a byte it was not granted is
/// `Pending` half the time, and every read may be short. The driver grants
/// what `NeedBytes` asked for. Deterministic for a seed.
pub struct Chaos {
    bytes: Vec<u8>,
    state: u64,
    granted: Vec<ByteRange>,
    pub pendings: u32,
}

impl Chaos {
    pub fn new(bytes: Vec<u8>, seed: u64) -> Self {
        Self {
            bytes,
            state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
            granted: Vec::new(),
            pendings: 0,
        }
    }

    fn next(&mut self) -> u64 {
        // xorshift64
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn grant(&mut self, range: ByteRange) {
        self.granted.push(range);
    }
}

impl ByteSource for Chaos {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset >= self.len() || buf.is_empty() {
            return Ok(0);
        }
        let granted = self.granted.iter().any(|r| r.start <= offset && offset < r.end);
        if !granted && self.next() % 2 == 0 {
            self.pendings += 1;
            let end = (offset + buf.len() as u64).min(self.len());
            return Err(SourceError::Pending(ByteRange::new(offset, end)));
        }
        let start = offset as usize;
        let max = buf.len().min(self.bytes.len() - start);
        let n = 1 + (self.next() as usize) % max;
        buf[..n].copy_from_slice(&self.bytes[start..start + n]);
        Ok(n)
    }
}

/// Step a session until it lists or refuses; `on_need` answers demands.
pub fn drive<S: ByteSource>(
    session: &mut ArchiveSession<S>,
    mut on_need: impl FnMut(&mut S, ByteRange),
) -> SessionStep {
    for _ in 0..1_000_000 {
        match session.step() {
            SessionStep::NeedBytes(range) => on_need(session.source_mut(), range),
            other => return other,
        }
    }
    panic!("the session never finished");
}

pub fn list_on(bytes: Vec<u8>, platform: ArchivePlatform) -> Result<ArchiveListing, ArchiveRefusal> {
    let mut session = ArchiveSession::open(Blocking(bytes), platform);
    match drive(&mut session, |_, range| {
        panic!("a blocking source was asked for {range:?}")
    }) {
        SessionStep::Listed => Ok(session.listing().expect("listed").clone()),
        SessionStep::Refused(refusal) => Err(refusal),
        other => panic!("unexpected {other:?}"),
    }
}

pub fn list(bytes: Vec<u8>) -> Result<ArchiveListing, ArchiveRefusal> {
    list_on(bytes, ArchivePlatform::Native)
}

pub fn list_chaos(bytes: Vec<u8>, seed: u64) -> (Result<ArchiveListing, ArchiveRefusal>, u32) {
    let mut session = ArchiveSession::open(Chaos::new(bytes, seed), ArchivePlatform::Native);
    let step = drive(&mut session, |source, range| source.grant(range));
    let pendings = session.source_mut().pendings;
    match step {
        SessionStep::Listed => (Ok(session.listing().expect("listed").clone()), pendings),
        SessionStep::Refused(refusal) => (Err(refusal), pendings),
        other => panic!("unexpected {other:?}"),
    }
}

/// Read one entry whole from a listed blocking session: its plaintext and
/// how it ended.
pub fn read_entry<S: ByteSource>(session: &mut ArchiveSession<S>, index: u32) -> (Vec<u8>, PieceStep) {
    let mut reader = session.entry_reader(index, None).expect("entry reader");
    let mut out = Vec::new();
    loop {
        match reader.next_piece() {
            PieceStep::Data(piece) => {
                assert!(piece.len() <= 64 * 1024, "a piece of {} bytes", piece.len());
                out.extend_from_slice(&piece);
            }
            PieceStep::NeedBytes(range) => panic!("a blocking source was asked for {range:?}"),
            end => return (out, end),
        }
    }
}

// ---------------------------------------------------------------- tar

pub struct TarBuilder {
    out: Vec<u8>,
    pub ustar: bool,
}

impl Default for TarBuilder {
    fn default() -> Self {
        Self {
            out: Vec::new(),
            ustar: true,
        }
    }
}

pub fn octal(value: u64, width: usize) -> Vec<u8> {
    let mut field = format!("{value:0w$o}", w = width - 1).into_bytes();
    field.push(0);
    field
}

pub fn tar_header(name: &[u8], typeflag: u8, size_field: &[u8], ustar: bool) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0001750\0");
    h[116..124].copy_from_slice(b"0001750\0");
    h[124..124 + size_field.len()].copy_from_slice(size_field);
    h[136..148].copy_from_slice(b"14707362000\0"); // 2026-…, any fixed time
    h[156] = typeflag;
    if ustar {
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
    }
    seal_checksum(&mut h);
    h
}

pub fn seal_checksum(h: &mut [u8; 512]) {
    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

impl TarBuilder {
    pub fn v7() -> Self {
        Self {
            out: Vec::new(),
            ustar: false,
        }
    }

    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.out.extend_from_slice(bytes);
        self
    }

    pub fn entry(&mut self, name: &str, typeflag: u8, data: &[u8]) -> &mut Self {
        let header = tar_header(name.as_bytes(), typeflag, &octal(data.len() as u64, 12), self.ustar);
        self.out.extend_from_slice(&header);
        self.data(data)
    }

    pub fn data(&mut self, data: &[u8]) -> &mut Self {
        self.out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.out.extend(std::iter::repeat_n(0u8, pad));
        self
    }

    pub fn file(&mut self, name: &str, data: &[u8]) -> &mut Self {
        self.entry(name, b'0', data)
    }

    pub fn folder(&mut self, name: &str) -> &mut Self {
        self.entry(name, b'5', b"")
    }

    pub fn pax(&mut self, records: &[(&str, &str)]) -> &mut Self {
        let mut body = Vec::new();
        for (key, value) in records {
            let rest = key.len() + value.len() + 3; // ' ', '=', '\n'
            let mut len = rest + 1;
            while len != rest + len.to_string().len() {
                len = rest + len.to_string().len();
            }
            body.extend_from_slice(format!("{len} {key}={value}\n").as_bytes());
        }
        self.entry("./PaxHeaders/x", b'x', &body)
    }

    pub fn gnu_long(&mut self, name: &str) -> &mut Self {
        let mut body = name.as_bytes().to_vec();
        body.push(0);
        self.entry("././@LongLink", b'L', &body)
    }

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.out);
        out.extend_from_slice(&[0u8; 1024]);
        out
    }
}

// ---------------------------------------------------------------- gzip

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub fn gzip_named(name: &str, data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::GzBuilder::new()
        .filename(name)
        .mtime(1_700_000_000)
        .write(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// One gzip member holding `len` zero bytes, written directly: a single
/// fixed-Huffman deflate block of a literal 0 and (258, distance 1) copies.
/// Building it costs microseconds per MiB, so tests can stream hundreds of
/// MiB without compressing them first. `len` must be at least 1.
pub fn gzip_zeros_member(len: u64) -> Vec<u8> {
    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }
    impl Bits {
        fn put(&mut self, value: u64, bits: u32) {
            self.acc |= value << self.n;
            self.n += bits;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }
        /// A Huffman code, most significant bit first.
        fn code(&mut self, code: u64, bits: u32) {
            let mut reversed = 0;
            for i in 0..bits {
                reversed |= ((code >> i) & 1) << (bits - 1 - i);
            }
            self.put(reversed, bits);
        }
    }
    assert!(len >= 1);
    let mut bits = Bits {
        out: vec![0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0xFF],
        acc: 0,
        n: 0,
    };
    bits.put(1, 1); // BFINAL
    bits.put(1, 2); // BTYPE = fixed Huffman
    bits.code(0x30, 8); // literal 0
    let mut left = len - 1;
    while left > 0 {
        // A copy is 3..=258 bytes; avoid leaving 1 or 2 behind.
        let n = if left > 258 && left < 261 {
            left - 3
        } else {
            left.min(258)
        };
        if n < 3 {
            bits.code(0x30, 8);
            left -= 1;
            continue;
        }
        let (code, extra_bits, base) = length_code(n);
        if code <= 279 {
            bits.code(code - 256, 7);
        } else {
            bits.code(0xC0 + code - 280, 8);
        }
        bits.put(n - base, extra_bits);
        bits.code(0, 5); // distance 1
        left -= n;
    }
    bits.code(0, 7); // end of block
    if bits.n > 0 {
        bits.put(0, 8 - bits.n); // flush to a byte
    }
    let mut out = bits.out;
    let mut crc = flate2::Crc::new();
    let chunk = vec![0u8; 1 << 20];
    let mut chunk_crc = flate2::Crc::new();
    chunk_crc.update(&chunk);
    let mut remaining = len;
    while remaining >= chunk.len() as u64 {
        crc.combine(&chunk_crc);
        remaining -= chunk.len() as u64;
    }
    crc.update(&chunk[..remaining as usize]);
    out.extend_from_slice(&crc.sum().to_le_bytes());
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out
}

/// The deflate length code for a copy of `n` bytes: (code, extra bits, base).
fn length_code(n: u64) -> (u64, u32, u64) {
    const TABLE: [(u64, u32, u64); 29] = [
        (257, 0, 3),
        (258, 0, 4),
        (259, 0, 5),
        (260, 0, 6),
        (261, 0, 7),
        (262, 0, 8),
        (263, 0, 9),
        (264, 0, 10),
        (265, 1, 11),
        (266, 1, 13),
        (267, 1, 15),
        (268, 1, 17),
        (269, 2, 19),
        (270, 2, 23),
        (271, 2, 27),
        (272, 2, 31),
        (273, 3, 35),
        (274, 3, 43),
        (275, 3, 51),
        (276, 3, 59),
        (277, 4, 67),
        (278, 4, 83),
        (279, 4, 99),
        (280, 4, 115),
        (281, 5, 131),
        (282, 5, 163),
        (283, 5, 195),
        (284, 5, 227),
        (285, 0, 258),
    ];
    *TABLE.iter().rev().find(|(_, _, base)| *base <= n).expect("n >= 3")
}
