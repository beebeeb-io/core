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

/// From this many plaintext bytes an entry is written as ZIP64. The format needs it at `u32::MAX` bytes; the 1 GiB
/// below that covers DEFLATE's worst-case growth of the compressed size (about 0.01%) and a `size_bytes` that is only
/// the server's word. Smaller entries keep the plain layout every reader opens.
const ZIP64_ENTRY_FROM_BYTES: u64 = 3 << 30;

/// Decrypts `entries` chunk by chunk into a ZIP archive on `writer`.
///
/// - `bytes_done` counts plaintext. `bytes_total` starts as the sum of the entries' `size_bytes`, and each entry's
///   share is replaced by the plaintext read once its last chunk is in, so the last event is exactly 100% whether
///   the uploader declared plaintext or encrypted sizes (the server accepts both).
/// - An entry whose path an earlier entry already has (compared as a case- and normalisation-insensitive drive
///   would) is stored as `name (2).ext`, `name (3).ext`, ...; no entry loses its own name to a rename.
/// - An entry is written as ZIP64 from 3 GiB of declared `size_bytes`. A server that declares less than 3 GiB for an
///   entry that streams past 4 GiB fails the archive with an `Err`, never with a corrupt one.
/// - **On `Err` (or a panic in a callback) the output is not an archive:** the central directory is never written,
///   so no reader opens it as a complete, shorter archive. The caller deletes it.
#[allow(clippy::type_complexity)]
pub fn stream_folder_zip<W: Write + Seek>(
    master_key: &MasterKey,
    entries: &[ZipEntry],
    fetch_chunk: &mut dyn FnMut(&str, u32) -> Result<Vec<u8>, CoreError>,
    writer: W,
    on_progress: &dyn Fn(&ZipProgress),
    cancel: &AtomicBool,
) -> Result<(), CoreError> {
    let mut bytes_total: u64 = entries.iter().map(|e| e.size_bytes).sum();
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

        let mut entry_done: u64 = 0;
        for chunk_idx in 0..entry.chunk_count {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled);
            }

            let encrypted = fetch_chunk(&entry.file_id, chunk_idx)?;
            let plaintext = decryptor.push_frame(&encrypted)?.data;

            zip.write_all(&plaintext).map_err(|e| CoreError::Io(e.to_string()))?;

            entry_done += plaintext.len() as u64;
            bytes_done += plaintext.len() as u64;
            // `size_bytes` is in the unit the uploading client declared (web: plaintext, cli: encrypted; the server
            // accepts both), so once an entry's last chunk is in, its declared size gives way to what was read.
            if chunk_idx + 1 == entry.chunk_count {
                bytes_total = bytes_total.saturating_sub(entry.size_bytes).saturating_add(entry_done);
            }

            on_progress(&ZipProgress {
                bytes_done,
                bytes_total,
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

pub fn estimate_zip_size(entries: &[ZipEntry]) -> u64 {
    entries.iter().map(|e| e.size_bytes).sum()
}

/// The archive path of each entry, in order. The first entry of a name keeps it; a later one gets ` (2)`, ` (3)`, ...
/// before the extension of its last path component, the way the cli names a duplicate, and never a name another
/// entry has. Names compare through [`crate::backup::fold_name`]: macOS and Windows extract case- and
/// normalisation-insensitively, so `Scan.PDF` would overwrite `scan.pdf` there.
fn unique_archive_paths(entries: &[ZipEntry]) -> Vec<String> {
    let mut taken = HashSet::with_capacity(entries.len());
    let keeps_name: Vec<bool> = entries
        .iter()
        .map(|entry| taken.insert(crate::backup::fold_name(&entry.path)))
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
                if taken.insert(crate::backup::fold_name(&candidate)) {
                    break candidate;
                }
                n += 1;
            }
        })
        .collect()
}

/// `path` with `suffix` before the extension of its last component (`v1.2/README` has none).
fn path_with_suffix(path: &str, suffix: &str) -> String {
    match path.rsplit_once('/') {
        Some((folder, name)) => format!("{folder}/{}", crate::sync::conflict::with_suffix(name, suffix)),
        None => crate::sync::conflict::with_suffix(path, suffix),
    }
}

/// The archive's byte sink. Once `sealed`, every write, flush and seek fails. Without that, dropping a half-written
/// [`ZipWriter`] finishes the current entry with a short CRC and writes a central directory, and the truncated output
/// reads as a complete, shorter archive.
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

impl<W: Write> Write for SealableWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check_open()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.check_open()?;
        self.inner.flush()
    }
}

impl<W: Seek> Seek for SealableWriter<'_, W> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.check_open()?;
        self.inner.seek(pos)
    }
}

/// Seals a [`SealableWriter`] when dropped.
struct SealOnExit<'a>(&'a Cell<bool>);

impl Drop for SealOnExit<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}
