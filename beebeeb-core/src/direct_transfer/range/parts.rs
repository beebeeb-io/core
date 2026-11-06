//! The range-read rules that are plain arithmetic (LD-0105 spec S1, S8, C3): which chunks a
//! demand needs, how released plaintext is cut into 4 KiB-aligned pieces, how many chunks a
//! session may hold, how big a window is, and the process byte budget across sessions.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::direct_transfer::window::Geometry;
use crate::direct_transfer::wire::{CHUNK_OVERHEAD, MAX_WINDOW};

/// Pieces handed to the OS start on this boundary and are a multiple of it long, unless they
/// end on the end of the file (Cloud Files TRANSFER_DATA, spec D-3).
pub const PIECE_ALIGN: u64 = 4096;
/// The most storage chunk requests one range session holds at once (spec S8).
pub const MAX_STORAGE_IN_FLIGHT: u32 = 16;
/// Pinned per-chunk API requests one range session runs at once (spec S10). The plain per-chunk
/// API route outside a session keeps its own limit of 1 (desktop).
pub const API_IN_FLIGHT: u32 = 4;
/// The smallest window a range session asks for (core's `DEFAULT_WINDOW`).
pub const MIN_RANGE_WINDOW: u32 = 8;
/// At most this many range sessions hold a budget lease at once; a further session waits for
/// one (spec S8: floor-1 slots mean `k` sessions always hold `k` chunks).
pub const MAX_SESSION_LEASES: usize = 4;

/// Chunks one session may hold (fetching, or fetched and not yet released) on a byte `share`:
/// `clamp(floor(share / (chunk_size + 28)), 1, 16)`. One chunk is always allowed, so a chunk
/// larger than the share is still fetched, alone (C3).
pub fn storage_in_flight(share_bytes: u64, chunk_size: u64) -> u32 {
    let held = chunk_size.saturating_add(CHUNK_OVERHEAD).max(1);
    u32::try_from(share_bytes / held)
        .unwrap_or(u32::MAX)
        .clamp(1, MAX_STORAGE_IN_FLIGHT)
}

/// Grants a range session asks per window: `min(server max_window, max(8, slots + 2))`. The
/// server's number is clamped to `1..=MAX_WINDOW` first, so an untrusted value cannot raise it.
pub fn range_window(server_max_window: u32, slots: u32) -> u32 {
    let server = server_max_window.clamp(1, MAX_WINDOW);
    server.min(MIN_RANGE_WINDOW.max(slots.saturating_add(2)))
}

/// One leased session's byte share of the process budget: `budget / leased` (never divided by 0).
pub fn session_share(budget_bytes: u64, leased: usize) -> u64 {
    budget_bytes / (leased.max(1) as u64)
}

/// The chunks (inclusive) a demand for plaintext `[offset, offset + len)` needs. The range is
/// first widened to whole 4 KiB pieces (clipped to the end of the file), because a piece that
/// straddles a chunk boundary can only be handed over once both chunks are out. `None` for a
/// demand that asks for nothing inside the file. An empty file has one (empty) chunk, and any
/// demand at offset 0 maps to it.
pub fn demand_chunks(geometry: &Geometry, offset: u64, len: u64) -> Option<(u32, u32)> {
    let size = geometry.original_size;
    let n = geometry.chunk_count;
    if n == 0 {
        return None;
    }
    if size == 0 {
        return (offset == 0).then_some((0, 0));
    }
    if len == 0 || offset >= size || geometry.chunk_size == 0 {
        return None;
    }
    let start = offset / PIECE_ALIGN * PIECE_ALIGN;
    let end = offset.saturating_add(len).min(size);
    let end = end.div_ceil(PIECE_ALIGN).saturating_mul(PIECE_ALIGN).min(size);
    let last_index = u64::from(n - 1);
    let first = (start / geometry.chunk_size).min(last_index) as u32;
    let last = ((end - 1) / geometry.chunk_size).min(last_index) as u32;
    Some((first, last))
}

/// A set of `u64` values kept as sorted, disjoint, non-adjacent half-open runs. Its size grows
/// with the number of gaps, never with the file: a front-to-back read is one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunSet {
    runs: Vec<(u64, u64)>,
}

impl RunSet {
    pub fn new() -> RunSet {
        RunSet::default()
    }

    /// Add `[start, end)`. An empty range adds nothing.
    pub fn insert(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let (mut s, mut e) = (start, end);
        let i = self.runs.partition_point(|&(_, re)| re < s);
        let mut j = i;
        while j < self.runs.len() && self.runs[j].0 <= e {
            s = s.min(self.runs[j].0);
            e = e.max(self.runs[j].1);
            j += 1;
        }
        self.runs.splice(i..j, [(s, e)]);
    }

    pub fn contains(&self, v: u64) -> bool {
        let i = self.runs.partition_point(|&(_, re)| re <= v);
        i < self.runs.len() && self.runs[i].0 <= v
    }

    /// Is every value of `[start, end)` in the set? (An empty range is.)
    pub fn covers(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return true;
        }
        let i = self.runs.partition_point(|&(_, re)| re <= start);
        i < self.runs.len() && self.runs[i].0 <= start && self.runs[i].1 >= end
    }

    /// The smallest value `>= from` that is not in the set.
    pub fn first_missing_from(&self, from: u64) -> u64 {
        let i = self.runs.partition_point(|&(_, re)| re <= from);
        if i < self.runs.len() && self.runs[i].0 <= from {
            self.runs[i].1
        } else {
            from
        }
    }

    /// How many values the set holds.
    pub fn len(&self) -> u64 {
        self.runs.iter().map(|&(s, e)| e - s).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    pub fn runs(&self) -> &[(u64, u64)] {
        &self.runs
    }
}

/// One piece of plaintext ready for the OS, in file order within one [`PieceCutter::cut`].
/// `Debug` prints offset and length only, never the bytes (I8).
#[derive(PartialEq, Eq)]
pub enum Piece {
    /// `plain[start..end]` of the chunk just cut, at file offset `offset`.
    Slice { offset: u64, start: usize, end: usize },
    /// A 4 KiB piece (or the file's last, shorter one) assembled from two neighbouring chunks.
    Block { offset: u64, data: Zeroizing<Vec<u8>> },
}

impl std::fmt::Debug for Piece {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Piece {{ offset: {}, len: {} }}", self.offset(), self.len())
    }
}

impl Piece {
    pub fn offset(&self) -> u64 {
        match self {
            Piece::Slice { offset, .. } | Piece::Block { offset, .. } => *offset,
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Piece::Slice { start, end, .. } => (end - start) as u64,
            Piece::Block { data, .. } => data.len() as u64,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of this piece; `plain` is the chunk that was cut.
    pub fn bytes<'a>(&'a self, plain: &'a [u8]) -> &'a [u8] {
        match self {
            Piece::Slice { start, end, .. } => &plain[*start..*end],
            Piece::Block { data, .. } => data,
        }
    }
}

/// Why released plaintext cannot be cut: a caller's bug, never a property of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CutError {
    #[error("the plaintext runs past the end of the file")]
    PastEof,
    #[error("the plaintext overlaps bytes that were already cut")]
    Overlap,
}

struct Block {
    data: Zeroizing<Vec<u8>>,
    filled: RunSet,
}

/// Cuts authenticated chunk plaintext into pieces the OS accepts: each starts on a 4 KiB
/// boundary and is a multiple of 4 KiB long unless it ends on the end of the file (S1). The
/// unaligned head or tail of a chunk is carried in a 4 KiB block until the neighbouring chunk
/// fills it, so this works for any chunk size, including 1 MiB and sizes that are not a
/// multiple of 4 KiB, and for chunks released in any order. What it holds is at most two partial
/// blocks per gap, in `Zeroizing` buffers. `Debug` never prints them (I8).
pub struct PieceCutter {
    file_size: u64,
    blocks: BTreeMap<u64, Block>,
}

impl std::fmt::Debug for PieceCutter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PieceCutter")
            .field("file_size", &self.file_size)
            .field("partial_blocks", &self.blocks.len())
            .field("held_bytes", &self.held_bytes())
            .finish()
    }
}

impl PieceCutter {
    pub fn new(file_size: u64) -> PieceCutter {
        PieceCutter {
            file_size,
            blocks: BTreeMap::new(),
        }
    }

    /// Plaintext bytes held in partial blocks.
    pub fn held_bytes(&self) -> u64 {
        self.blocks.values().map(|b| b.filled.len()).sum()
    }

    /// Cut `plain`, which sits at file offset `offset`. The pieces come back in file order.
    pub fn cut(&mut self, offset: u64, plain: &[u8]) -> Result<Vec<Piece>, CutError> {
        let end = offset.checked_add(plain.len() as u64).ok_or(CutError::PastEof)?;
        if end > self.file_size {
            return Err(CutError::PastEof);
        }
        let mut pieces = Vec::new();
        if plain.is_empty() {
            return Ok(pieces);
        }
        let a = PIECE_ALIGN;
        let first_full = offset.div_ceil(a) * a;
        let last_full_end = if end == self.file_size { end } else { end / a * a };
        if first_full > offset {
            let head = offset / a * a;
            if let Some(piece) = self.partial(head, offset, end.min(first_full), offset, plain)? {
                pieces.push(piece);
            }
        }
        if first_full < last_full_end {
            pieces.push(Piece::Slice {
                offset: first_full,
                start: (first_full - offset) as usize,
                end: (last_full_end - offset) as usize,
            });
        }
        if last_full_end < end && last_full_end >= first_full {
            if let Some(piece) = self.partial(last_full_end, last_full_end, end, offset, plain)? {
                pieces.push(piece);
            }
        }
        Ok(pieces)
    }

    /// Copy `[from, to)` of the chunk at `offset` into the block at `block`; the block comes back
    /// once every byte of it is there.
    fn partial(
        &mut self,
        block: u64,
        from: u64,
        to: u64,
        offset: u64,
        plain: &[u8],
    ) -> Result<Option<Piece>, CutError> {
        let block_len = (block + PIECE_ALIGN).min(self.file_size) - block;
        let entry = self.blocks.entry(block).or_insert_with(|| Block {
            data: Zeroizing::new(vec![0u8; block_len as usize]),
            filled: RunSet::new(),
        });
        let (lo, hi) = (from - block, to - block);
        if entry.filled.runs().iter().any(|&(s, e)| s < hi && lo < e) {
            return Err(CutError::Overlap);
        }
        entry.data[lo as usize..hi as usize].copy_from_slice(&plain[(from - offset) as usize..(to - offset) as usize]);
        entry.filled.insert(lo, hi);
        if entry.filled.covers(0, block_len) {
            let Some(done) = self.blocks.remove(&block) else {
                return Ok(None);
            };
            return Ok(Some(Piece::Block {
                offset: block,
                data: done.data,
            }));
        }
        Ok(None)
    }
}

/// The process byte budget that range sessions lease (spec S8), as a pure book: who holds a lease
/// and how many ciphertext bytes each holds. `beebeeb-transfer` wraps it in a lock and wakes the
/// sessions that wait.
///
/// Two rules, both checked before a session starts a fetch ([`RangeBudget::try_hold`]):
/// - its own share: `held + len <= max(share, len)`, where `share = budget / leased` (one chunk
///   is always allowed, so a chunk larger than the share is fetched alone);
/// - the whole process: `total + len <= max(budget, leased * len)`.
///
/// So the ciphertext held never exceeds `max(budget, leased * (chunk + 28))`, and at most
/// [`MAX_SESSION_LEASES`] sessions hold a lease.
#[derive(Debug, Clone)]
pub struct RangeBudget {
    budget: u64,
    leases: BTreeMap<u64, u64>,
}

impl RangeBudget {
    pub fn new(budget_bytes: u64) -> RangeBudget {
        RangeBudget {
            budget: budget_bytes,
            leases: BTreeMap::new(),
        }
    }

    /// Take a lease for `session`. `false` when [`MAX_SESSION_LEASES`] sessions already hold one
    /// (the session waits). A session that holds one already keeps it (`true`).
    pub fn lease(&mut self, session: u64) -> bool {
        if self.leases.contains_key(&session) {
            return true;
        }
        if self.leases.len() >= MAX_SESSION_LEASES {
            return false;
        }
        self.leases.insert(session, 0);
        true
    }

    /// Give the lease back, with whatever the session still held. Returns those bytes.
    pub fn release(&mut self, session: u64) -> u64 {
        self.leases.remove(&session).unwrap_or(0)
    }

    pub fn leased(&self) -> usize {
        self.leases.len()
    }

    pub fn is_leased(&self, session: u64) -> bool {
        self.leases.contains_key(&session)
    }

    /// One leased session's share now.
    pub fn share(&self) -> u64 {
        session_share(self.budget, self.leases.len())
    }

    pub fn held(&self, session: u64) -> u64 {
        self.leases.get(&session).copied().unwrap_or(0)
    }

    pub fn total_held(&self) -> u64 {
        self.leases.values().sum()
    }

    /// May `session` hold `len` more bytes? If so they are booked to it.
    pub fn try_hold(&mut self, session: u64, len: u64) -> bool {
        let leased = self.leases.len() as u64;
        let share = self.share();
        let total = self.total_held();
        let Some(held) = self.leases.get_mut(&session) else {
            return false;
        };
        let own = held.saturating_add(len) <= share.max(len);
        let process = total.saturating_add(len) <= self.budget.max(leased.saturating_mul(len));
        if own && process {
            *held += len;
            true
        } else {
            false
        }
    }

    /// `session` no longer holds `len` bytes (the chunk was released or its fetch failed).
    pub fn unhold(&mut self, session: u64, len: u64) {
        if let Some(held) = self.leases.get_mut(&session) {
            *held = held.saturating_sub(len);
        }
    }
}
