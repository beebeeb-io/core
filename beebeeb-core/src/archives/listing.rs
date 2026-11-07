//! Builds a listing: implied folders, folder merging, the entry cap,
//! totals and protection. Shared by every format.

use std::collections::HashMap;

use super::detect::ArchiveFormat;
use super::limits::MAX_ENTRIES;
use super::model::{ArchiveEntry, ArchiveListing, ArchiveRefusal, ArchiveTotals, EntryCipher, EntryKind, Protection};
use super::names::EntryPath;

/// Where an entry's bytes are, for the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Locator {
    /// No bytes: an implied folder, a folder, a link.
    None,
    /// A tar entry: its ordinal and the stream offset of its data (the
    /// file offset in a plain tar, the decompressed offset in a tgz).
    Tar { ordinal: u32, data_offset: u64, size: u64 },
    /// The one file of a `.gz`.
    Gzip,
}

#[derive(Default)]
pub(crate) struct ListingBuilder {
    pub entries: Vec<ArchiveEntry>,
    pub locators: Vec<Locator>,
    folders: HashMap<Vec<String>, u32>,
}

impl ListingBuilder {
    /// Add an entry (its `index` is assigned here) and any folder its path
    /// implies. A folder entry whose path is already listed as a folder is
    /// merged into it. Returns the entry's index.
    pub(crate) fn push(&mut self, mut entry: ArchiveEntry, locator: Locator) -> Result<u32, ArchiveRefusal> {
        if let Some(path) = entry.path.clone() {
            for depth in 1..path.components.len() {
                let prefix = path.components[..depth].to_vec();
                if !self.folders.contains_key(&prefix) {
                    let folder = EntryPath {
                        components: prefix.clone(),
                    };
                    let index = self.add(
                        ArchiveEntry {
                            index: 0,
                            display_path: folder.joined(),
                            path: Some(folder),
                            kind: EntryKind::Folder,
                            size: 0,
                            compressed_size: 0,
                            cipher: EntryCipher::None,
                            modified: None,
                            skip: None,
                        },
                        Locator::None,
                    )?;
                    self.folders.insert(prefix, index);
                }
            }
            if entry.kind == EntryKind::Folder && entry.skip.is_none() {
                if let Some(&existing) = self.folders.get(&path.components) {
                    let listed = &mut self.entries[existing as usize];
                    if listed.modified.is_none() {
                        listed.modified = entry.modified;
                    }
                    return Ok(existing);
                }
                entry.display_path = path.joined();
                let index = self.add(entry, locator)?;
                self.folders.insert(path.components, index);
                return Ok(index);
            }
        }
        self.add(entry, locator)
    }

    fn add(&mut self, mut entry: ArchiveEntry, locator: Locator) -> Result<u32, ArchiveRefusal> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(ArchiveRefusal::TooMany);
        }
        let index = self.entries.len() as u32;
        entry.index = index;
        self.entries.push(entry);
        self.locators.push(locator);
        Ok(index)
    }

    pub(crate) fn finish(self, format: ArchiveFormat, complete: bool) -> (ArchiveListing, Vec<Locator>) {
        let mut totals = ArchiveTotals::default();
        let mut encrypted = 0u32;
        let mut uses_zipcrypto = false;
        for entry in &self.entries {
            match entry.kind {
                EntryKind::File => {
                    totals.files += 1;
                    totals.bytes = totals.bytes.saturating_add(entry.size);
                    totals.compressed_bytes = totals.compressed_bytes.saturating_add(entry.compressed_size);
                    if entry.cipher.is_encrypted() {
                        encrypted += 1;
                    }
                }
                EntryKind::Folder => totals.folders += 1,
                _ => {}
            }
            uses_zipcrypto |= entry.cipher == EntryCipher::ZipCrypto;
            if entry.skip.is_some() {
                totals.skipped += 1;
            }
        }
        let protection = match encrypted {
            0 => Protection::None,
            n if n == totals.files => Protection::All,
            _ => Protection::Some,
        };
        let listing = ArchiveListing {
            format,
            entries: self.entries,
            totals,
            protection,
            uses_zipcrypto,
            complete,
        };
        (listing, self.locators)
    }
}
