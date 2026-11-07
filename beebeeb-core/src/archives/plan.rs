//! The extraction planner (spec §5.2): pure, and run before anything is
//! written. It names the destination and every node, numbers clashes
//! (1022 G5: auto-name, no question; the first entry in archive order keeps
//! its name), lists what is skipped and why, and refuses an extraction the
//! limits, the quota, the device or Backups do not allow.

use std::collections::HashMap;

use beebeeb_types::limits::ENCRYPTED_FRAME_OVERHEAD_BYTES;

use super::detect::ArchiveFormat;
use super::limits::{MAX_ENTRIES, MAX_EXTRACTION_BYTES};
use super::model::{ArchiveListing, ArchiveTotals, EntryKind, SkipReason};
use super::platform::ArchivePlatform;
use super::words::{ArchiveKey, ArchiveText, archive_text, count_label, size_label};
use crate::backup::BackupPosition;
use crate::name_clash::{ItemKind, TakenNames, numbered_name};

/// Which entries to extract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    All,
    /// Paths as the listing shows them; a folder selects everything in it.
    Paths(Vec<String>),
}

/// Where the extraction lands.
#[derive(Debug, Clone)]
pub struct DestinationInfo {
    /// The decrypted names already in the destination folder.
    pub siblings: TakenNames,
    /// The destination folder's place relative to Backups; `None` when the
    /// account has no Backups root.
    pub backup_position: Option<BackupPosition>,
    /// Whether the person can add files there.
    pub writable: bool,
}

#[derive(Debug, Clone)]
pub struct ExtractRequest {
    pub archive_name: String,
    pub selection: Selection,
    pub destination: DestinationInfo,
    /// Free storage on the account (the server owns the quota).
    pub server_free_bytes: u64,
    /// Free disk on a device that stages files before uploading them.
    pub device_free_bytes: Option<u64>,
    pub platform: ArchivePlatform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    Folder,
    File,
}

/// A folder or file the extraction creates. `parent: None` is the folder
/// the archive is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedNode {
    pub id: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub kind: NodeKind,
    /// The listing entry a file comes from.
    pub entry: Option<u32>,
    pub size: u64,
}

/// What the extraction creates next to the archive: a folder, or for a
/// plain `.gz` the one file (A9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanTarget {
    Folder(u32),
    File(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionPlan {
    pub target: PlanTarget,
    /// Folders first where they appear, every parent before its children.
    pub nodes: Vec<PlannedNode>,
    /// Listing entries not extracted, and why.
    pub skipped: Vec<(u32, SkipReason)>,
    /// Listing entries saved under another name, and that name.
    pub renamed: Vec<(u32, String)>,
    pub totals: ArchiveTotals,
    pub notices: Vec<ArchiveText>,
}

/// Why nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanRefusal {
    TooMany,
    TooLarge {
        total: u64,
    },
    Quota {
        needed: u64,
        free: u64,
    },
    DeviceSpace {
        needed: u64,
        free: u64,
    },
    Backups,
    ReadOnlyFolder,
    /// Nothing to extract: the archive (or the selection) is empty.
    Empty,
}

impl PlanRefusal {
    /// The refusal's words (spec §9).
    pub fn text(&self) -> ArchiveText {
        match self {
            PlanRefusal::TooMany => archive_text(ArchiveKey::RefuseTooMany, &[]),
            PlanRefusal::TooLarge { total } => archive_text(
                ArchiveKey::RefuseTooLarge,
                &[
                    ("size", &size_label(*total)),
                    ("limit", &size_label(MAX_EXTRACTION_BYTES)),
                ],
            ),
            PlanRefusal::Quota { needed, free } => archive_text(
                ArchiveKey::RefuseQuota,
                &[("needed", &size_label(*needed)), ("free", &size_label(*free))],
            ),
            PlanRefusal::DeviceSpace { needed, free } => archive_text(
                ArchiveKey::RefuseDeviceSpace,
                &[("needed", &size_label(*needed)), ("free", &size_label(*free))],
            ),
            PlanRefusal::Backups => archive_text(ArchiveKey::RefuseBackups, &[]),
            PlanRefusal::ReadOnlyFolder => archive_text(ArchiveKey::RefuseReadOnlyFolder, &[]),
            PlanRefusal::Empty => archive_text(ArchiveKey::ArchiveEmpty, &[]),
        }
    }
}

/// The destination's name: the archive's name without the last of
/// `.tar.gz`, `.tgz`, `.tar`, `.zip`, `.gz` (any case); an empty or
/// dots-only stem is `Archive`.
pub fn destination_stem(archive_name: &str) -> String {
    let lower = archive_name.to_ascii_lowercase();
    let cut = [".tar.gz", ".tgz", ".tar", ".zip", ".gz"]
        .iter()
        .find(|suffix| lower.ends_with(*suffix))
        .map_or(0, |suffix| suffix.len());
    let stem = &archive_name[..archive_name.len() - cut];
    if stem.chars().all(|c| c == '.') {
        "Archive".to_string()
    } else {
        stem.to_string()
    }
}

/// A file's size once stored: its plaintext plus one frame overhead per
/// chunk, by core's chunk plan for the platform's uploads.
fn stored_size(size: u64, platform: ArchivePlatform) -> u64 {
    let chunks = beebeeb_types::plan_chunks(size, platform.chunk_profile()).chunk_count;
    size.saturating_add(chunks.saturating_mul(ENCRYPTED_FRAME_OVERHEAD_BYTES))
}

fn free_name(name: &str, kind: ItemKind, taken: &TakenNames) -> String {
    if taken.contains(name) {
        numbered_name(name, kind, taken)
    } else {
        name.to_string()
    }
}

fn selected(selection: &Selection, display_path: &str) -> bool {
    match selection {
        Selection::All => true,
        Selection::Paths(paths) => paths.iter().any(|p| {
            let p = p.trim_end_matches('/');
            display_path == p || display_path.strip_prefix(p).is_some_and(|rest| rest.starts_with('/'))
        }),
    }
}

struct Builder {
    nodes: Vec<PlannedNode>,
    /// Names taken in each folder node.
    taken: HashMap<u32, TakenNames>,
    /// Folder nodes by (parent, the archive's own component name).
    folders: HashMap<(u32, String), u32>,
    renamed: Vec<(u32, String)>,
}

impl Builder {
    fn add(&mut self, parent: u32, wanted: &str, kind: NodeKind, entry: Option<u32>, size: u64) -> u32 {
        let item = if kind == NodeKind::Folder {
            ItemKind::Folder
        } else {
            ItemKind::File
        };
        let taken = self.taken.entry(parent).or_default();
        let name = free_name(wanted, item, taken);
        taken.insert(&name);
        if name != wanted
            && let Some(entry) = entry
        {
            self.renamed.push((entry, name.clone()));
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(PlannedNode {
            id,
            parent: Some(parent),
            name,
            kind,
            entry,
            size,
        });
        id
    }

    /// The folder node for `component` under `parent`, created (and
    /// numbered when its name is taken) the first time.
    fn folder(&mut self, parent: u32, component: &str, entry: Option<u32>) -> u32 {
        if let Some(&id) = self.folders.get(&(parent, component.to_string())) {
            return id;
        }
        let id = self.add(parent, component, NodeKind::Folder, entry, 0);
        self.folders.insert((parent, component.to_string()), id);
        id
    }
}

pub fn plan_extraction(listing: &ArchiveListing, request: &ExtractRequest) -> Result<ExtractionPlan, PlanRefusal> {
    if request
        .destination
        .backup_position
        .is_some_and(|p| p != BackupPosition::Outside)
    {
        return Err(PlanRefusal::Backups);
    }
    if !request.destination.writable {
        return Err(PlanRefusal::ReadOnlyFolder);
    }
    let chosen: Vec<_> = listing
        .entries
        .iter()
        .filter(|e| selected(&request.selection, &e.display_path))
        .collect();
    if chosen.is_empty() {
        return Err(PlanRefusal::Empty);
    }
    let stem = destination_stem(&request.archive_name);
    let max_entry = request.platform.max_entry_bytes();
    let mut skipped = Vec::new();
    let mut too_large_here = 0u64;

    let mut builder = Builder {
        nodes: Vec::new(),
        taken: HashMap::new(),
        folders: HashMap::new(),
        renamed: Vec::new(),
    };
    let target = if listing.format == ArchiveFormat::Gzip {
        let entry = chosen[0];
        let name = free_name(&stem, ItemKind::File, &request.destination.siblings);
        builder.nodes.push(PlannedNode {
            id: 0,
            parent: None,
            name,
            kind: NodeKind::File,
            entry: Some(entry.index),
            size: entry.size,
        });
        PlanTarget::File(0)
    } else {
        let name = free_name(&stem, ItemKind::Folder, &request.destination.siblings);
        builder.nodes.push(PlannedNode {
            id: 0,
            parent: None,
            name,
            kind: NodeKind::Folder,
            entry: None,
            size: 0,
        });
        for entry in &chosen {
            let reason = match (&entry.skip, &entry.path) {
                (Some(reason), _) => Some(reason.clone()),
                (None, None) => Some(SkipReason::UnusableName),
                (None, Some(_)) if entry.kind == EntryKind::File && entry.size > max_entry => {
                    too_large_here += 1;
                    Some(SkipReason::TooLarge)
                }
                (None, Some(_)) if !matches!(entry.kind, EntryKind::File | EntryKind::Folder) => {
                    Some(SkipReason::Unsupported("Not a file or folder".into()))
                }
                (None, Some(_)) => None,
            };
            if let Some(reason) = reason {
                skipped.push((entry.index, reason));
                continue;
            }
            let Some(path) = &entry.path else { continue };
            let (last, parents) = path.components.split_last().expect("a path has a component");
            let mut parent = 0;
            for component in parents {
                parent = builder.folder(parent, component, None);
            }
            if entry.kind == EntryKind::Folder {
                builder.folder(parent, last, Some(entry.index));
            } else {
                builder.add(parent, last, NodeKind::File, Some(entry.index), entry.size);
            }
            if builder.nodes.len() > MAX_ENTRIES + 1 {
                return Err(PlanRefusal::TooMany);
            }
        }
        PlanTarget::Folder(0)
    };

    let mut totals = ArchiveTotals {
        skipped: skipped.len() as u32,
        ..ArchiveTotals::default()
    };
    let mut stored = 0u64;
    let mut largest = 0u64;
    for node in &builder.nodes {
        match node.kind {
            NodeKind::File => {
                totals.files += 1;
                totals.bytes = totals.bytes.saturating_add(node.size);
                stored = stored.saturating_add(stored_size(node.size, request.platform));
                largest = largest.max(node.size);
            }
            NodeKind::Folder if node.parent.is_some() => totals.folders += 1,
            NodeKind::Folder => {}
        }
    }
    if totals.bytes > MAX_EXTRACTION_BYTES {
        return Err(PlanRefusal::TooLarge { total: totals.bytes });
    }
    if stored > request.server_free_bytes {
        return Err(PlanRefusal::Quota {
            needed: stored,
            free: request.server_free_bytes,
        });
    }
    if let Some(free) = request.device_free_bytes
        && largest > free
    {
        return Err(PlanRefusal::DeviceSpace { needed: largest, free });
    }
    let mut notices = Vec::new();
    if too_large_here > 0 && request.platform == ArchivePlatform::Browser {
        notices.push(archive_text(
            ArchiveKey::RefuseWebEntryTooLarge,
            &[("n", &count_label(too_large_here)), ("limit", &size_label(max_entry))],
        ));
    }
    Ok(ExtractionPlan {
        target,
        nodes: builder.nodes,
        skipped,
        renamed: builder.renamed,
        totals,
        notices,
    })
}
