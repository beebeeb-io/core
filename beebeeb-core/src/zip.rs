use std::cell::Cell;
use std::collections::HashSet;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use zip::CompressionMethod;
use zip::write::{SimpleFileOptions, ZipWriter};

use crate::CoreError;
use crate::chunk_stream::{ChunkDecryptor, ExpectedChunkFormat, VersionCommitment};
use crate::kdf::{MasterKey, derive_file_key};

pub struct ZipEntry {
    pub path: String,
    pub file_id: String,
    pub chunk_count: u32,
    pub size_bytes: u64,
    /// From the entry's encrypted metadata
    /// ([`crate::encrypt::decrypt_file_metadata`]) — task 1908.
    pub chunk_format: ExpectedChunkFormat,
    /// The version commitment from the same metadata record. A v2 entry opens
    /// only as the upload it names; with `None` only a v1 entry opens (Guus's
    /// ruling of 2026-11-07, "refuse v2 without commitment").
    pub version: Option<VersionCommitment>,
}

pub struct ZipProgress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub file_index: usize,
    pub file_count: usize,
    pub current_file: String,
}

/// From this declared `size_bytes` an entry is written as ZIP64. The declared size is in the uploader's unit,
/// plaintext or encrypted (see LD-0147), which differ by 28 bytes a chunk. The format needs ZIP64 at `u32::MAX` bytes
/// of content; the 1 GiB below that covers that difference, DEFLATE's worst-case growth of the compressed size (about
/// 0.01%) and a `size_bytes` that is only the server's word. Smaller entries keep the plain layout every reader opens.
const ZIP64_ENTRY_FROM_BYTES: u64 = 3 << 30;

/// Decrypts `entries` chunk by chunk into a ZIP archive on `writer`.
///
/// - `bytes_done` counts plaintext. `bytes_total` starts as the sum of the entries' `size_bytes`, and each entry's
///   share is replaced by the plaintext read once its last chunk is in, so the last event is exactly 100% whether
///   the uploader declared plaintext or encrypted sizes (the server accepts both). No event reports more than 100%,
///   whatever the declared sizes say, and an understated size does not make the fraction done fall back later.
/// - An entry whose path an earlier entry already has (compared as a case- and normalisation-insensitive drive
///   would, without empty components such as `a//b`) is stored as `name (2).ext`, `name (3).ext`, ...; no entry loses
///   its own name to a rename. Paths are `/`-separated and relative, as the cli's `archive_component` makes them.
/// - An entry is written as ZIP64 from 3 GiB of declared `size_bytes`. A server that declares less than 3 GiB for an
///   entry that streams past 4 GiB fails the archive with an `Err`, never with a corrupt one.
/// - **On `Err` (or a panic in a callback) the output is unfinished:** the writer is sealed at the first failure, so
///   no central directory follows it and no reader opens the output as a complete, shorter archive. The one
///   exception is a sink that fails on the last seek after the footer is written: the footer is then already there.
///   The caller deletes the output on any `Err`.
#[allow(clippy::type_complexity)]
pub fn stream_folder_zip<W: Write + Seek>(
    master_key: &MasterKey,
    entries: &[ZipEntry],
    fetch_chunk: &mut dyn FnMut(&str, u32) -> Result<Vec<u8>, CoreError>,
    writer: W,
    on_progress: &dyn Fn(&ZipProgress),
    cancel: &AtomicBool,
) -> Result<(), CoreError> {
    let mut bytes_total = declared_total(entries);
    let mut bytes_done: u64 = 0;
    let file_count = entries.len();
    let archive_paths = unique_archive_paths(entries);

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6));

    // `_seal_on_exit` drops before `zip`, whichever way this function ends, and seals the writer; only the finished
    // archive below writes its footer first.
    let sealed = Cell::new(false);
    let mut zip = ZipWriter::new(SealableWriter {
        inner: writer,
        sealed: &sealed,
    });
    let _seal_on_exit = SealOnExit(&sealed);

    for (file_index, entry) in entries.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled);
        }

        // Task 1908: one ordered decrypt stream per entry, so a reordered,
        // spliced or truncated chunk list fails instead of zipping garbage.
        let mut decryptor = ChunkDecryptor::for_version_with_file_key(
            derive_file_key(master_key, entry.file_id.as_bytes()),
            &entry.file_id,
            entry.chunk_format,
            entry.version,
        );

        zip.start_file(
            &archive_paths[file_index],
            options.large_file(entry.size_bytes >= ZIP64_ENTRY_FROM_BYTES),
        )
        .map_err(|e| CoreError::Io(e.to_string()))?;

        let entry_start = bytes_done;
        for chunk_idx in 0..entry.chunk_count {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled);
            }

            let encrypted = fetch_chunk(&entry.file_id, chunk_idx)?;
            let plaintext = decryptor.push_frame(&encrypted)?.data;

            zip.write_all(&plaintext).map_err(|e| CoreError::Io(e.to_string()))?;

            bytes_done += plaintext.len() as u64;
            let entry_so_far = bytes_done - entry_start;
            let last_chunk = chunk_idx + 1 == entry.chunk_count;
            // `size_bytes` is in the unit the uploading client declared (web: plaintext, cli: encrypted; the server
            // accepts both, LD-0147), so once an entry's last chunk is in, its declared size gives way to what was read.
            if last_chunk {
                bytes_total = bytes_total
                    .saturating_sub(entry.size_bytes)
                    .saturating_add(entry_so_far);
            }
            // Until then, an entry that already holds more than it declared counts for what it holds: the total grows
            // with it, so no event is above 100% and the fraction done does not fall back when the entry ends.
            let overshoot = if last_chunk {
                0
            } else {
                entry_so_far.saturating_sub(entry.size_bytes)
            };

            on_progress(&ZipProgress {
                bytes_done,
                // The last guard, for sums that saturated.
                bytes_total: bytes_total.saturating_add(overshoot).max(bytes_done),
                file_index,
                file_count,
                current_file: entry.path.clone(),
            });
        }
        // `chunk_count` comes from the server; a v2 file whose count was
        // understated ends before its last chunk and is rejected here.
        decryptor.finish()?;
    }

    zip.finish().map_err(|e| CoreError::Io(e.to_string()))?;
    Ok(())
}

/// The sum of the entries' declared `size_bytes`, in the uploader's unit (plaintext or encrypted, LD-0147), so it can
/// differ by 28 bytes a chunk from the plaintext the archive ends up holding. Saturates instead of overflowing.
pub fn estimate_zip_size(entries: &[ZipEntry]) -> u64 {
    declared_total(entries)
}

fn declared_total(entries: &[ZipEntry]) -> u64 {
    entries.iter().fold(0u64, |total, e| total.saturating_add(e.size_bytes))
}

/// The archive path of each entry, in order. The first entry of a name keeps it; a later one gets ` (2)`, ` (3)`, ...
/// before the extension of its last path component, the way the cli names a duplicate, and never a name another
/// entry has or a folder of another entry (a file named like one is renamed too). Names compare through
/// [`path_key`]: macOS and Windows extract case- and normalisation-insensitively, so `Scan.PDF` would overwrite
/// `scan.pdf` there.
fn unique_archive_paths(entries: &[ZipEntry]) -> Vec<String> {
    // Every folder of every entry is taken before any file: a file never shares its path with another entry's folder.
    // Entries come folder by folder, so a folder that equals the previous entry's is not looked at again.
    let mut folders: HashSet<String> = HashSet::new();
    let mut previous_folder = None;
    for entry in entries {
        let folder = entry.path.rsplit_once('/').map(|(folder, _)| folder);
        if folder != previous_folder {
            folders.extend(folder.into_iter().flat_map(folder_chain));
            previous_folder = folder;
        }
    }
    let mut taken: HashSet<String> = folders.iter().map(|folder| crate::backup::fold_name(folder)).collect();
    let keeps_name: Vec<bool> = entries
        .iter()
        .map(|entry| taken.insert(path_key(&entry.path)))
        .collect();
    entries
        .iter()
        .zip(keeps_name)
        .map(|(entry, keeps_name)| {
            if keeps_name {
                return entry.path.clone();
            }
            let mut n: u64 = 2;
            loop {
                let candidate = path_with_suffix(&entry.path, &format!(" ({n})"));
                if taken.insert(path_key(&candidate)) {
                    break candidate;
                }
                n += 1;
            }
        })
        .collect()
}

/// How an extractor sees `path` when it compares names: the components without the empty ones (`a//b` is `a/b`, a
/// leading `/` is dropped), folded by [`crate::backup::fold_name`].
fn path_key(path: &str) -> String {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    crate::backup::fold_name(&components.join("/"))
}

/// The folders on the way to `folder`, as unfolded keys without empty components: `a/b` gives `a` and `a/b`.
fn folder_chain(folder: &str) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    for component in folder.split('/').filter(|c| !c.is_empty()) {
        let next = match chain.last() {
            Some(parent) => format!("{parent}/{component}"),
            None => component.to_string(),
        };
        chain.push(next);
    }
    chain
}

/// `path` with `suffix` before the extension of its last component (`v1.2/README` has none).
fn path_with_suffix(path: &str, suffix: &str) -> String {
    match path.rsplit_once('/') {
        Some((folder, name)) => format!("{folder}/{}", crate::sync::conflict::with_suffix(name, suffix)),
        None => crate::sync::conflict::with_suffix(path, suffix),
    }
}

/// The archive's byte sink. Once `sealed`, every write, flush and seek fails, and the first failure of the sink seals
/// it. Without that, dropping a half-written [`ZipWriter`] finishes the current entry with a short CRC and writes a
/// central directory, and the truncated output reads as a complete, shorter archive.
struct SealableWriter<'a, W> {
    inner: W,
    sealed: &'a Cell<bool>,
}

impl<W> SealableWriter<'_, W> {
    fn check_open(&self) -> std::io::Result<()> {
        if self.sealed.get() {
            return Err(std::io::Error::other(
                "the archive was abandoned before it was finished",
            ));
        }
        Ok(())
    }
}

/// Runs one call on the sink. `Interrupted` is retried here and never surfaces: `write_all` would retry it, but the zip
/// crate does not retry a seek or a flush, and one that failed would make `ZipWriter::finish` return `Err`. Any other
/// failure seals the writer for good. `finish` drops the writer inside itself when it fails and its `Drop` finalizes a
/// second time; a sink that works again by then would get a second central directory after the partial first one, and
/// the output would read as a complete archive although the caller got an `Err`. (A failure of the zip crate itself, not
/// of the sink, repeats identically on that second try and writes no footer either.)
fn run_sealing<T>(sealed: &Cell<bool>, mut call: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    loop {
        match call() {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                sealed.set(true);
                return Err(e);
            }
            Ok(value) => return Ok(value),
        }
    }
}

impl<W: Write> Write for SealableWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check_open()?;
        let written = run_sealing(self.sealed, || self.inner.write(buf))?;
        if written == 0 && !buf.is_empty() {
            // `write_all` turns this into `WriteZero`; the sink is not taking bytes.
            self.sealed.set(true);
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.check_open()?;
        run_sealing(self.sealed, || self.inner.flush())
    }
}

impl<W: Seek> Seek for SealableWriter<'_, W> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.check_open()?;
        run_sealing(self.sealed, || self.inner.seek(pos))
    }
}

/// Seals a [`SealableWriter`] when dropped.
struct SealOnExit<'a>(&'a Cell<bool>);

impl Drop for SealOnExit<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// A sink whose next call fails in the way set, then works again.
    struct Flaky {
        inner: Cursor<Vec<u8>>,
        interrupts: u32,
        fail: Option<std::io::ErrorKind>,
        zero_bytes: bool,
        calls: u32,
    }

    impl Flaky {
        fn new() -> Self {
            Self {
                inner: Cursor::new(Vec::new()),
                interrupts: 0,
                fail: None,
                zero_bytes: false,
                calls: 0,
            }
        }

        fn gate(&mut self) -> std::io::Result<()> {
            self.calls += 1;
            if self.interrupts > 0 {
                self.interrupts -= 1;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            match self.fail.take() {
                Some(kind) => Err(kind.into()),
                None => Ok(()),
            }
        }
    }

    impl Write for Flaky {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.gate()?;
            if std::mem::take(&mut self.zero_bytes) {
                return Ok(0);
            }
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.gate()
        }
    }

    impl Seek for Flaky {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.gate()?;
            self.inner.seek(pos)
        }
    }

    #[test]
    fn interrupted_calls_are_retried_and_do_not_seal() {
        let sealed = Cell::new(false);
        let mut sink = Flaky::new();
        sink.interrupts = 3;
        let mut writer = SealableWriter {
            inner: sink,
            sealed: &sealed,
        };
        assert_eq!(writer.write(b"abc").unwrap(), 3);
        writer.inner.interrupts = 2;
        writer.flush().unwrap();
        writer.inner.interrupts = 2;
        assert_eq!(writer.seek(SeekFrom::Start(1)).unwrap(), 1);
        assert!(!sealed.get(), "an interrupted call must not seal the writer");
        assert!(writer.inner.calls >= 3 + 2 + 2 + 3, "each interrupted call was retried");
    }

    fn call(writer: &mut SealableWriter<'_, Flaky>, which: &str) -> std::io::Result<()> {
        match which {
            "write" => writer.write(b"x").map(drop),
            "flush" => writer.flush(),
            _ => writer.seek(SeekFrom::Start(0)).map(drop),
        }
    }

    #[test]
    fn a_failed_write_flush_or_seek_seals_the_writer_for_good() {
        for name in ["write", "flush", "seek"] {
            let sealed = Cell::new(false);
            let mut sink = Flaky::new();
            sink.fail = Some(std::io::ErrorKind::Other);
            let mut writer = SealableWriter {
                inner: sink,
                sealed: &sealed,
            };
            assert!(call(&mut writer, name).is_err(), "{name}: the failure must surface");
            assert!(sealed.get(), "{name}: a failure of the sink must seal the writer");
            let calls = writer.inner.calls;
            // The sink works again, but the writer stays shut and does not touch it.
            for again in ["write", "flush", "seek"] {
                assert!(
                    call(&mut writer, again).is_err(),
                    "{name}, then {again}: must stay sealed"
                );
            }
            assert_eq!(
                writer.inner.calls, calls,
                "{name}: a sealed writer must not call the sink"
            );
        }
    }

    #[test]
    fn a_write_of_zero_bytes_seals_the_writer() {
        let sealed = Cell::new(false);
        let mut sink = Flaky::new();
        sink.zero_bytes = true;
        let mut writer = SealableWriter {
            inner: sink,
            sealed: &sealed,
        };
        assert_eq!(writer.write(b"abc").unwrap(), 0);
        assert!(sealed.get());
        assert!(writer.write(b"abc").is_err());
        // An empty buffer taking zero bytes is not a failure.
        let sealed = Cell::new(false);
        let mut writer = SealableWriter {
            inner: Flaky::new(),
            sealed: &sealed,
        };
        assert_eq!(writer.write(b"").unwrap(), 0);
        assert!(!sealed.get());
    }
}
