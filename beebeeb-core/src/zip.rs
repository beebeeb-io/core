use std::io::{Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

use crate::encrypt::decrypt_chunk_raw;
use crate::kdf::{derive_file_key, MasterKey};
use crate::CoreError;

pub struct ZipEntry {
    pub path: String,
    pub file_id: String,
    pub chunk_count: u32,
    pub size_bytes: u64,
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

        let file_key = derive_file_key(master_key, entry.file_id.as_bytes());

        zip.start_file(&entry.path, options)
            .map_err(|e| CoreError::Io(e.to_string()))?;

        for chunk_idx in 0..entry.chunk_count {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled);
            }

            let encrypted = fetch_chunk(&entry.file_id, chunk_idx)?;
            let plaintext = decrypt_chunk_raw(&file_key, &encrypted)?;

            zip.write_all(&plaintext)
                .map_err(|e| CoreError::Io(e.to_string()))?;

            bytes_done += encrypted.len() as u64;

            on_progress(&ZipProgress {
                bytes_done,
                bytes_total,
                file_index,
                file_count,
                current_file: entry.path.clone(),
            });
        }
    }

    zip.finish().map_err(|e| CoreError::Io(e.to_string()))?;
    Ok(())
}

pub fn estimate_zip_size(entries: &[ZipEntry]) -> u64 {
    entries.iter().map(|e| e.size_bytes).sum()
}
