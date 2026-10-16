use std::io::{Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use zip::CompressionMethod;
use zip::write::{SimpleFileOptions, ZipWriter};

use crate::CoreError;
use crate::chunk_stream::{ChunkDecryptor, ExpectedChunkFormat};
use crate::kdf::MasterKey;

pub struct ZipEntry {
    pub path: String,
    pub file_id: String,
    pub chunk_count: u32,
    pub size_bytes: u64,
    /// From the entry's encrypted metadata
    /// ([`crate::encrypt::decrypt_name_metadata`]) — task 1908. `V2` accepts
    /// only v2 frames; `Unrecorded` (legacy metadata) lets chunk 0 decide.
    pub chunk_format: ExpectedChunkFormat,
}

pub struct ZipProgress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub file_index: usize,
    pub file_count: usize,
    pub current_file: String,
}

#[allow(clippy::type_complexity)]
pub fn stream_folder_zip<W: Write + Seek>(
    master_key: &MasterKey,
    entries: &[ZipEntry],
    fetch_chunk: &mut dyn FnMut(&str, u32) -> Result<Vec<u8>, CoreError>,
    writer: W,
    on_progress: &dyn Fn(&ZipProgress),
    cancel: &AtomicBool,
) -> Result<(), CoreError> {
    let bytes_total: u64 = entries.iter().map(|e| e.size_bytes).sum();
    let mut bytes_done: u64 = 0;
    let file_count = entries.len();

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6));

    let mut zip = ZipWriter::new(writer);

    for (file_index, entry) in entries.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled);
        }

        // Task 1908: one ordered decrypt stream per entry, so a reordered,
        // spliced or truncated chunk list fails instead of zipping garbage.
        let mut decryptor = ChunkDecryptor::for_push(master_key, &entry.file_id, entry.chunk_format);

        zip.start_file(&entry.path, options)
            .map_err(|e| CoreError::Io(e.to_string()))?;

        for chunk_idx in 0..entry.chunk_count {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled);
            }

            let encrypted = fetch_chunk(&entry.file_id, chunk_idx)?;
            let plaintext = decryptor.push_frame(&encrypted)?.data;

            zip.write_all(&plaintext).map_err(|e| CoreError::Io(e.to_string()))?;

            bytes_done += encrypted.len() as u64;

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
