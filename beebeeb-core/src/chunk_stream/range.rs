//! [`RangeOpener`]: the random-access opener a range session releases plaintext through
//! (LD-0105 D1; core `docs/agent-notes.md`, range reads I1–I9).
//!
//! It opens ONE whole AEAD frame at the index the caller requested and returns its plaintext
//! only after the tag passed (I1). Everything that positions a frame comes from the session's
//! one geometry, never from the frame or the server's answer for it (I2): `is_last = (index ==
//! n - 1)`, and the plaintext length must be the geometry's `chunk_length(index) - 28`. The
//! identity is fixed once (I3): the format comes from the content pin; frame 0 opens first (it
//! decides an `Unrecorded` file's format and carries a v2 file's version id), and every later
//! frame opens under that format and version id only, never by detection. The v2 chunk subkey is
//! derived once, and the plaintext comes back `Zeroizing` (I8).
//!
//! What it does NOT give v1 (every file written today, `WRITE_FORMAT = V1Legacy`): v1 frames carry
//! no position, version or truncation binding, so equal-length frames of one file key can be
//! reordered, duplicated or spliced from another version, and the file truncated at a chunk
//! boundary. That is the same gap the whole-file read has (I9; test T5 pins it).
//!
//! [`RangeOpener::finish`] is the only "whole" verdict: every index `0..n` was opened in this
//! attempt (for v2 that includes the last frame, which only opens as last). A caller that
//! released frames and then gets `Err` anywhere must treat its sink as poisoned (I4, I5).

use zeroize::Zeroizing;

use super::{
    ChunkDecryptorSummary, ChunkFormat, ExpectedChunkFormat, VERSION_ID_LEN, chunk_aad_v2, derive_chunk_key_v2,
    version_id_of,
};
use crate::CoreError;
use crate::direct_transfer::range::RunSet;
use crate::direct_transfer::window::Geometry;
use crate::encrypt::open_raw_with_aad;
use crate::kdf::FileKey;

/// Opens the chunks of ONE version of one file, at any index, in any order after frame 0.
pub struct RangeOpener {
    file_key: FileKey,
    /// v2 chunk subkey, derived once.
    chunk_key: FileKey,
    file_id: Vec<u8>,
    pin: ExpectedChunkFormat,
    geometry: Geometry,
    format: Option<ChunkFormat>,
    version_id: Option<[u8; VERSION_ID_LEN]>,
    opened: RunSet,
}

impl std::fmt::Debug for RangeOpener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeOpener")
            .field("pin", &self.pin)
            .field("geometry", &self.geometry)
            .field("format", &self.format)
            .field("opened", &self.opened.len())
            .finish_non_exhaustive()
    }
}

impl RangeOpener {
    /// `pin` is the content pin from `decrypt_file_metadata[_with_key]` (never a server value);
    /// `geometry` is the session's one geometry; `expected_size` is the size the OS holds for the
    /// file (the placeholder's `FileSize`). A geometry no real version has, or one whose
    /// `original_size` differs from `expected_size`, is refused: nothing may be released (I2).
    pub fn new(
        file_key: FileKey,
        file_id: &str,
        pin: ExpectedChunkFormat,
        geometry: Geometry,
        expected_size: u64,
    ) -> Result<RangeOpener, CoreError> {
        if !geometry.is_consistent() {
            return Err(CoreError::InvalidInput(
                "the geometry is not that of any real version".into(),
            ));
        }
        if geometry.original_size != expected_size {
            return Err(CoreError::InvalidInput(
                "the geometry's size is not the size the file is known to have".into(),
            ));
        }
        Ok(RangeOpener {
            chunk_key: derive_chunk_key_v2(&file_key),
            file_key,
            file_id: file_id.as_bytes().to_vec(),
            pin,
            geometry,
            format: None,
            version_id: None,
            opened: RunSet::new(),
        })
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// The format frame 0 established (`None` before frame 0 opened).
    pub fn format(&self) -> Option<ChunkFormat> {
        self.format
    }

    /// A v2 file's version id (frame 0's nonce), once frame 0 authenticated.
    pub fn version_id(&self) -> Option<[u8; VERSION_ID_LEN]> {
        self.version_id
    }

    pub fn is_opened(&self, index: u32) -> bool {
        self.opened.contains(u64::from(index))
    }

    pub fn opened_count(&self) -> u64 {
        self.opened.len()
    }

    /// Where chunk `index`'s plaintext starts in the file: `index * chunk_size` (I2).
    pub fn plaintext_offset(&self, index: u32) -> Option<u64> {
        (index < self.geometry.chunk_count).then(|| u64::from(index) * self.geometry.chunk_size)
    }

    /// Chunk `index`'s plaintext length: `chunk_length(index) - 28` (I2).
    pub fn plaintext_len(&self, index: u32) -> Option<u64> {
        self.geometry.chunk_length(index)?.checked_sub(super::CHUNK_OVERHEAD)
    }

    /// Open `frame` as chunk `index`. On `Err` nothing is released and nothing about the
    /// session changes (a refused frame 0 does not lock a format).
    pub fn open(&mut self, index: u32, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let n = self.geometry.chunk_count;
        if index >= n {
            return Err(CoreError::InvalidInput("chunk index outside the file".into()));
        }
        if self.is_opened(index) {
            return Err(CoreError::InvalidInput("chunk already opened in this session".into()));
        }
        if self.format.is_none() && index != 0 {
            return Err(CoreError::InvalidInput("frame 0 must open first".into()));
        }
        let expected_len = self.plaintext_len(index).ok_or(CoreError::Decryption)?;
        let is_last = index + 1 == n;
        let (plain, format, version_id) = match (self.format, self.version_id) {
            (Some(ChunkFormat::V2), Some(vid)) => {
                (self.open_v2(&vid, index, is_last, frame)?, ChunkFormat::V2, Some(vid))
            }
            (Some(ChunkFormat::V2), None) => return Err(CoreError::Decryption),
            (Some(ChunkFormat::V1Legacy), _) => (self.open_v1(frame)?, ChunkFormat::V1Legacy, None),
            (None, _) => self.open_frame0(is_last, frame)?,
        };
        if plain.len() as u64 != expected_len {
            return Err(CoreError::Decryption);
        }
        self.format = Some(format);
        self.version_id = version_id;
        self.opened.insert(u64::from(index), u64::from(index) + 1);
        Ok(plain)
    }

    fn open_v2(
        &self,
        vid: &[u8; VERSION_ID_LEN],
        index: u32,
        is_last: bool,
        frame: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let aad = chunk_aad_v2(&self.file_id, vid, index, is_last);
        open_raw_with_aad(&self.chunk_key, frame, &aad).map(Zeroizing::new)
    }

    fn open_v1(&self, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        open_raw_with_aad(&self.file_key, frame, &[]).map(Zeroizing::new)
    }

    /// Frame 0 fixes the identity: under a v2 pin it opens as v2 or not at all; an
    /// `Unrecorded` pin tries v2 first, then v1 (the one detection there is, for legacy files).
    #[allow(clippy::type_complexity)]
    fn open_frame0(
        &self,
        is_last: bool,
        frame: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, ChunkFormat, Option<[u8; VERSION_ID_LEN]>), CoreError> {
        let v2 = version_id_of(frame).and_then(|vid| self.open_v2(&vid, 0, is_last, frame).ok().map(|p| (p, vid)));
        match (self.pin, v2) {
            (_, Some((plain, vid))) => Ok((plain, ChunkFormat::V2, Some(vid))),
            (ExpectedChunkFormat::V2, None) => Err(CoreError::Decryption),
            (ExpectedChunkFormat::Unrecorded, None) => Ok((self.open_v1(frame)?, ChunkFormat::V1Legacy, None)),
        }
    }

    /// The only "whole" verdict (I6): every index `0..n` opened in this attempt. For v2 the last
    /// index only opens with `is_last = true`, so a truncated or extended v2 file never gets here.
    pub fn finish(&self) -> Result<ChunkDecryptorSummary, CoreError> {
        let n = self.geometry.chunk_count;
        match self.format {
            Some(format) if self.opened.covers(0, u64::from(n)) => Ok(ChunkDecryptorSummary { chunk_count: n, format }),
            _ => Err(CoreError::Decryption),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_stream::ChunkEncryptor;
    use crate::direct_transfer::wire::CHUNK_OVERHEAD;
    use crate::encrypt::encrypt_chunk_raw;

    const FILE: &str = "11111111-2222-4333-8444-555555555555";
    const OTHER_FILE: &str = "99999999-2222-4333-8444-555555555555";
    const KEY: [u8; 32] = [9u8; 32];
    const STRIDE: u64 = 1000;

    fn key() -> FileKey {
        FileKey::from_bytes(KEY)
    }

    fn plain(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Frames of `data` under `file_id`, in `format`.
    fn frames(file_id: &str, data: &[u8], format: ChunkFormat) -> Vec<Vec<u8>> {
        let mut enc = ChunkEncryptor::for_push_with_file_key(key(), file_id, data.len() as u64, STRIDE)
            .unwrap()
            .with_format(format)
            .unwrap();
        let out = data
            .chunks(STRIDE as usize)
            .map(|piece| enc.push_chunk(piece).unwrap().data)
            .collect();
        enc.finish().unwrap();
        out
    }

    fn geometry(chunk_count: u32, original_size: u64) -> Geometry {
        Geometry {
            chunk_count,
            chunk_size: STRIDE,
            encrypted_size: original_size + CHUNK_OVERHEAD * u64::from(chunk_count),
            original_size,
        }
    }

    fn opener(pin: ExpectedChunkFormat, g: Geometry) -> RangeOpener {
        RangeOpener::new(key(), FILE, pin, g, g.original_size).unwrap()
    }

    fn released_nothing(o: &RangeOpener, before: u64) {
        assert_eq!(o.opened_count(), before, "a refused frame changes nothing");
    }

    #[test]
    fn a_v2_file_opens_in_any_order_after_frame_0_and_finishes_whole() {
        let data = plain(3500, 1);
        let f = frames(FILE, &data, ChunkFormat::V2);
        let mut o = opener(ExpectedChunkFormat::V2, geometry(4, 3500));
        let mut out = vec![0u8; 3500];
        for i in [0u32, 3, 1, 2] {
            let p = o.open(i, &f[i as usize]).unwrap();
            let at = o.plaintext_offset(i).unwrap() as usize;
            out[at..at + p.len()].copy_from_slice(&p);
            assert!(
                o.opened_count() == 4 || o.finish().is_err(),
                "not whole before every index opened"
            );
        }
        assert_eq!(out, data);
        assert_eq!(o.finish().unwrap().format, ChunkFormat::V2);
    }

    #[test]
    fn frame_0_comes_first_and_no_index_opens_twice() {
        let f = frames(FILE, &plain(2500, 2), ChunkFormat::V2);
        let mut o = opener(ExpectedChunkFormat::V2, geometry(3, 2500));
        assert!(matches!(o.open(1, &f[1]), Err(CoreError::InvalidInput(_))));
        o.open(0, &f[0]).unwrap();
        o.open(1, &f[1]).unwrap();
        assert!(matches!(o.open(1, &f[1]), Err(CoreError::InvalidInput(_))));
        assert!(matches!(o.open(3, &f[2]), Err(CoreError::InvalidInput(_))));
    }

    #[test]
    fn the_size_must_be_the_size_the_file_is_known_to_have() {
        let g = geometry(3, 2500);
        assert!(RangeOpener::new(key(), FILE, ExpectedChunkFormat::V2, g, 2499).is_err());
        let mut bad = g;
        bad.encrypted_size += 1;
        assert!(RangeOpener::new(key(), FILE, ExpectedChunkFormat::V2, bad, 2500).is_err());
    }

    #[test]
    fn a_v2_pin_refuses_a_v1_frame_0() {
        let f = frames(FILE, &plain(2500, 3), ChunkFormat::V1Legacy);
        let mut o = opener(ExpectedChunkFormat::V2, geometry(3, 2500));
        assert!(o.open(0, &f[0]).is_err());
        assert_eq!(o.format(), None, "a refused frame 0 locks no format");
    }

    /// T1 (crypto review): index, duplicate, version and file binding. Mutant: the index comes
    /// from the server (the frame is tried at every index until one opens).
    #[test]
    fn t1_v2_frames_open_only_at_their_index_version_and_file() {
        let data = plain(3500, 4);
        let a = frames(FILE, &data, ChunkFormat::V2);
        let b = frames(FILE, &data, ChunkFormat::V2); // another upload of the same file id
        let x = frames(OTHER_FILE, &data, ChunkFormat::V2); // another file, same key
        let mut o = opener(ExpectedChunkFormat::V2, geometry(4, 3500));
        o.open(0, &a[0]).unwrap();
        // a frame served at another index
        assert!(o.open(2, &a[1]).is_err());
        released_nothing(&o, 1);
        o.open(1, &a[1]).unwrap();
        // a duplicate of chunk 1 at index 2
        assert!(o.open(2, &a[1]).is_err());
        released_nothing(&o, 2);
        // a frame of upload B while the session is pinned to A
        assert!(o.open(2, &b[2]).is_err());
        // a frame of file X used in file Y
        assert!(o.open(2, &x[2]).is_err());
        released_nothing(&o, 2);
        assert!(!o.is_opened(2));
        o.open(2, &a[2]).unwrap();
    }

    /// T2: the geometry claims n-1 or n+1 chunks. Mutant: `is_last` not bound from the geometry
    /// (the last frame never asserted, the `seen_last` check of the review).
    #[test]
    fn t2_a_v2_geometry_one_short_or_one_long_never_finishes() {
        let data = plain(4000, 5); // exactly 4 full chunks
        let f = frames(FILE, &data, ChunkFormat::V2);
        // n - 1: chunk 2 would be the last, but it was sealed as not last.
        let mut short = opener(ExpectedChunkFormat::V2, geometry(3, 3000));
        short.open(0, &f[0]).unwrap();
        short.open(1, &f[1]).unwrap();
        assert!(short.open(2, &f[2]).is_err(), "n-2 does not open as last");
        assert!(short.finish().is_err());
        // n + 1: chunk 3 was sealed as last, the geometry says it is not.
        let mut long = opener(ExpectedChunkFormat::V2, geometry(5, 4001));
        for i in 0..3u32 {
            long.open(i, &f[i as usize]).unwrap();
        }
        assert!(
            long.open(3, &f[3]).is_err(),
            "the real last chunk does not open as a middle one"
        );
        assert!(long.finish().is_err());
    }

    /// T3: an `Unrecorded` pin with a raw-key frame in a v2 file. Mutant: the format is detected
    /// per chunk.
    #[test]
    fn t3_an_unrecorded_v2_file_never_opens_a_raw_key_frame_later() {
        let data = plain(3000, 6);
        let mut f = frames(FILE, &data, ChunkFormat::V2);
        f[1] = encrypt_chunk_raw(&key(), &data[1000..2000]).unwrap();
        let mut o = opener(ExpectedChunkFormat::Unrecorded, geometry(3, 3000));
        o.open(0, &f[0]).unwrap();
        assert_eq!(o.format(), Some(ChunkFormat::V2), "frame 0 decided v2 and locked it");
        assert!(o.open(1, &f[1]).is_err());
        released_nothing(&o, 1);
    }

    /// T4: a plaintext length the geometry does not allow, for v1 and v2. Mutant: no length check.
    #[test]
    fn t4_a_length_the_geometry_does_not_allow_is_refused() {
        let data = plain(2500, 7);
        for (format, pin) in [
            (ChunkFormat::V1Legacy, ExpectedChunkFormat::Unrecorded),
            (ChunkFormat::V2, ExpectedChunkFormat::V2),
        ] {
            let f = frames(FILE, &data, format);
            // The geometry says the last chunk holds 499 bytes; its frame holds 500.
            let mut o = opener(pin, geometry(3, 2499));
            o.open(0, &f[0]).unwrap();
            o.open(1, &f[1]).unwrap();
            assert!(
                o.open(2, &f[2]).is_err(),
                "{format:?}: a 500-byte chunk where 499 belong"
            );
            released_nothing(&o, 2);
        }
        // v1: a valid, shorter frame under the same key where a full chunk belongs.
        let f = frames(FILE, &data, ChunkFormat::V1Legacy);
        let mut o = opener(ExpectedChunkFormat::Unrecorded, geometry(3, 2500));
        o.open(0, &f[0]).unwrap();
        let short = encrypt_chunk_raw(&key(), &data[1000..1900]).unwrap();
        assert!(o.open(1, &short).is_err());
    }

    /// T5 (characterisation, I9): v1 frames carry no position. Two equal-length v1 frames swapped
    /// both open, and the session even "finishes". This pins the gap; it is not a guarantee.
    #[test]
    fn t5_v1_frames_of_equal_length_swap_undetected() {
        let data = plain(3000, 8);
        let f = frames(FILE, &data, ChunkFormat::V1Legacy);
        let mut o = opener(ExpectedChunkFormat::Unrecorded, geometry(3, 3000));
        o.open(0, &f[0]).unwrap();
        let at_1 = o.open(1, &f[2]).unwrap();
        let at_2 = o.open(2, &f[1]).unwrap();
        assert_eq!(&at_1[..], &data[2000..3000], "chunk 2's bytes were released as chunk 1");
        assert_eq!(&at_2[..], &data[1000..2000]);
        assert!(o.finish().is_ok(), "v1 has no binding that could notice");
    }
}
