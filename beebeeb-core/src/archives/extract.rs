//! The extraction (spec §5.2): a sans-I/O step machine over a listed
//! session and its plan. Drivers carry out each step (create a folder,
//! stage and upload a file) and report back; core decides the order, the
//! names, when a file may be published and how the run ends.
//!
//! Folders come first, breadth-first; files follow in archive order (zip:
//! local header offset; tar: stream order). A file's bytes are handed out
//! as they are decoded, but `FileEnd` (publish) comes only after the
//! entry's own check passed (A6); anything else ends in `FileSkipped`.

use std::collections::{HashMap, HashSet, VecDeque};

use super::detect::ArchiveFormat;
use super::limits::{MAX_ENTRIES, MAX_EXTRACTION_BYTES};
use super::listing::Locator;
use super::model::{ArchiveListing, EntryKind, SkipReason};
use super::password::ArchivePassword;
use super::plan::{ExtractionPlan, NodeKind, PlanTarget, PlannedNode};
use super::session::{ArchiveSession, EntryDecoder, PieceStep, tar_entry, tgz_piece};
use super::source::{ByteRange, ByteSource};
use super::tar::{GzInput, Halt, TarEvent, TarHeader, TarInput, TarWalker};
use crate::name_clash::{ItemKind, TakenNames, numbered_name};

/// Why a run ended early.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailReason {
    StorageFull,
    Network,
    /// The archive's bytes stopped authenticating partway.
    Damaged,
    /// The archive got a new version.
    Changed,
    /// The account stopped allowing uploads (frozen, lapsed, trial cap).
    AccountBlocked,
}

impl FailReason {
    pub const ALL: [FailReason; 5] = [
        FailReason::StorageFull,
        FailReason::Network,
        FailReason::Damaged,
        FailReason::Changed,
        FailReason::AccountBlocked,
    ];

    /// The binding string.
    pub const fn as_str(self) -> &'static str {
        match self {
            FailReason::StorageFull => "storage_full",
            FailReason::Network => "network",
            FailReason::Damaged => "damaged",
            FailReason::Changed => "changed",
            FailReason::AccountBlocked => "account_blocked",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_str() == text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtractOutcome {
    Done,
    Stopped,
    Failed(FailReason),
}

impl ExtractOutcome {
    /// The binding string (the reason of `Failed` is separate).
    pub const fn as_str(self) -> &'static str {
        match self {
            ExtractOutcome::Done => "done",
            ExtractOutcome::Stopped => "stopped",
            ExtractOutcome::Failed(_) => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractProgress {
    /// Files whose upload finished.
    pub files_done: u32,
    pub files_total: u32,
    /// Plaintext bytes decoded so far.
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// The file being extracted now.
    pub current: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractSummary {
    pub outcome: ExtractOutcome,
    /// The destination folder's (or the one file's) final name.
    pub target_name: String,
    /// Files whose upload finished: exactly what is in the folder.
    pub files_done: u32,
    pub files_total: u32,
    /// Entries not extracted (their shown path), and why.
    pub skipped: Vec<(String, SkipReason)>,
    /// Entries saved under another name: (shown path, new name).
    pub renamed: Vec<(String, String)>,
}

/// What the driver does next. `Debug` shows a piece's length, never the
/// person's plaintext.
#[derive(Clone, PartialEq, Eq)]
pub enum ExtractStep {
    /// Supply these bytes to the source, then step again.
    NeedBytes(ByteRange),
    /// Ask the person for the password (`wrong`: the last one did not
    /// work), then `supply_password` or `cancel`.
    NeedPassword {
        entry: u32,
        wrong: bool,
    },
    /// Create this folder in `parent` (`None`: next to the archive), then
    /// `folder_created`, or `folder_name_taken` on a 409 race.
    CreateFolder {
        node: u32,
        parent: Option<u32>,
        name: String,
    },
    /// Start staging a file.
    FileBegin {
        node: u32,
        parent: Option<u32>,
        name: String,
        size: u64,
    },
    /// More of the file (not yet verified: stage it, never publish it).
    FileData {
        node: u32,
        bytes: Vec<u8>,
    },
    /// The file verified: upload it, then `upload_finished`.
    FileEnd {
        node: u32,
    },
    /// Drop whatever was staged for this file. A protected file whose
    /// password passed its check byte but not its CRC is skipped this way
    /// once, then asked for again (`NeedPassword` with `wrong`) and begun
    /// again (`FileBegin`, same `node`); the summary counts only the
    /// final outcome.
    FileSkipped {
        node: u32,
        reason: SkipReason,
    },
    Progress(ExtractProgress),
    /// Nothing to do until an upload finishes: step again after the next
    /// `upload_finished`.
    Waiting,
    Finished(ExtractSummary),
}

impl std::fmt::Debug for ExtractStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractStep::NeedBytes(range) => f.debug_tuple("NeedBytes").field(range).finish(),
            ExtractStep::NeedPassword { entry, wrong } => f
                .debug_struct("NeedPassword")
                .field("entry", entry)
                .field("wrong", wrong)
                .finish(),
            ExtractStep::CreateFolder { node, parent, name } => f
                .debug_struct("CreateFolder")
                .field("node", node)
                .field("parent", parent)
                .field("name", name)
                .finish(),
            ExtractStep::FileBegin {
                node,
                parent,
                name,
                size,
            } => f
                .debug_struct("FileBegin")
                .field("node", node)
                .field("parent", parent)
                .field("name", name)
                .field("size", size)
                .finish(),
            ExtractStep::FileData { node, bytes } => f
                .debug_struct("FileData")
                .field("node", node)
                .field("bytes", &format_args!("{} bytes", bytes.len()))
                .finish(),
            ExtractStep::FileEnd { node } => f.debug_struct("FileEnd").field("node", node).finish(),
            ExtractStep::FileSkipped { node, reason } => f
                .debug_struct("FileSkipped")
                .field("node", node)
                .field("reason", reason)
                .finish(),
            ExtractStep::Progress(progress) => f.debug_tuple("Progress").field(progress).finish(),
            ExtractStep::Waiting => f.write_str("Waiting"),
            ExtractStep::Finished(summary) => f.debug_tuple("Finished").field(summary).finish(),
        }
    }
}

/// The archive the extraction is bound to: one file at one version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArchiveIdentity {
    pub file_id: String,
    pub object_version_id: String,
}

struct Current {
    node: u32,
    entry: u32,
    encrypted: bool,
    decoder: Option<EntryDecoder>,
    /// For a tgz entry: whether the shared walker reached its header.
    tgz_found: bool,
    began: bool,
    /// Once the cipher is open: which password encoding opened it, and
    /// whether the entry passing its check proves the password.
    opened_with: Option<usize>,
    proves_password: bool,
    /// Bytes given out for this entry so far (taken back if it is read
    /// again).
    bytes: u64,
}

impl Current {
    fn new(node: u32, entry: u32, encrypted: bool) -> Self {
        Self {
            node,
            entry,
            encrypted,
            decoder: None,
            tgz_found: false,
            began: false,
            opened_with: None,
            proves_password: false,
            bytes: 0,
        }
    }
}

/// Naming state for entries a tgz holds past its (incomplete) listing.
struct Tail {
    taken: HashMap<u32, TakenNames>,
    folders: HashMap<(u32, String), u32>,
    /// A file node read but not yet extracted, waiting for its folders.
    pending: Option<u32>,
}

pub struct Extraction<S: ByteSource> {
    session: ArchiveSession<S>,
    identity: ArchiveIdentity,
    plan: ExtractionPlan,
    password: Option<ArchivePassword>,
    password_proven: bool,
    ask_wrong: bool,
    /// Protected entries already read again after a password that passed
    /// their check byte failed their CRC (each is read again once).
    retried: HashSet<u32>,
    folders: VecDeque<u32>,
    awaiting: Option<u32>,
    tried: HashMap<u32, TakenNames>,
    /// A raced folder's name before its first number.
    base_names: HashMap<u32, String>,
    remote: HashMap<u32, String>,
    files: VecDeque<u32>,
    current: Option<Current>,
    tgz: Option<Box<TarWalker<GzInput>>>,
    tail: Option<Tail>,
    tail_checked: bool,
    uploading: HashSet<u32>,
    files_done: u32,
    files_total: u32,
    bytes_done: u64,
    run_skips: Vec<(String, SkipReason)>,
    progress_due: bool,
    stop: Option<ExtractOutcome>,
    finished: Option<ExtractSummary>,
}

impl<S: ByteSource> Extraction<S> {
    /// Start extracting `plan` from a listed `session`, bound to
    /// `identity`. A password from the preview is passed on, so the person
    /// is not asked twice.
    pub fn start(
        session: ArchiveSession<S>,
        identity: ArchiveIdentity,
        plan: ExtractionPlan,
        password: Option<ArchivePassword>,
    ) -> Self {
        let mut x = Self {
            session,
            identity,
            plan,
            password,
            password_proven: false,
            ask_wrong: false,
            retried: HashSet::new(),
            folders: VecDeque::new(),
            awaiting: None,
            tried: HashMap::new(),
            base_names: HashMap::new(),
            remote: HashMap::new(),
            files: VecDeque::new(),
            current: None,
            tgz: None,
            tail: None,
            tail_checked: false,
            uploading: HashSet::new(),
            files_done: 0,
            files_total: 0,
            bytes_done: 0,
            run_skips: Vec::new(),
            progress_due: false,
            stop: None,
            finished: None,
        };
        if x.session.listing().is_none() {
            x.stop = Some(ExtractOutcome::Failed(FailReason::Damaged));
            return x;
        }
        x.queue();
        x
    }

    fn queue(&mut self) {
        let depth = |nodes: &[PlannedNode], mut id: u32| {
            let mut depth = 0u32;
            while let Some(parent) = nodes.get(id as usize).and_then(|n| n.parent) {
                id = parent;
                depth += 1;
            }
            depth
        };
        let nodes = &self.plan.nodes;
        let mut folders: Vec<(u32, u32)> = nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Folder)
            .map(|n| (depth(nodes, n.id), n.id))
            .collect();
        folders.sort_unstable();
        self.folders = folders.into_iter().map(|(_, id)| id).collect();
        let mut files: Vec<(u64, u32)> = nodes
            .iter()
            .filter(|n| n.kind == NodeKind::File)
            .map(|n| (self.archive_order(n.entry.unwrap_or(0)), n.id))
            .collect();
        files.sort_unstable();
        self.files_total = files.len() as u32;
        self.files = files.into_iter().map(|(_, id)| id).collect();
    }

    /// Where an entry's bytes are in the archive, for reading in order.
    fn archive_order(&self, entry: u32) -> u64 {
        match self.session.locator(entry) {
            Some(Locator::Zip(zip)) => zip.header_offset,
            Some(Locator::Tar { data_offset, .. }) => *data_offset,
            _ => u64::from(entry),
        }
    }

    /// The listing being extracted (for the preview while it runs).
    pub fn listing(&self) -> Option<&ArchiveListing> {
        self.session.listing()
    }

    /// The plan being extracted.
    pub fn plan(&self) -> &ExtractionPlan {
        &self.plan
    }

    pub fn source_mut(&mut self) -> &mut S {
        self.session.source_mut()
    }

    /// Whether a password is held now.
    pub fn holds_password(&self) -> bool {
        self.password.is_some()
    }

    pub fn folder_created(&mut self, node: u32, remote_id: String) {
        if self.awaiting == Some(node) {
            self.awaiting = None;
        }
        self.remote.insert(node, remote_id);
    }

    /// The folder's name was taken between planning and creating it (a
    /// `409 name_conflict`): it gets the next number.
    pub fn folder_name_taken(&mut self, node: u32) {
        let Some(planned) = self.plan.nodes.get_mut(node as usize) else {
            return;
        };
        let tried = self.tried.entry(node).or_default();
        tried.insert(&planned.name);
        let base = self.base_names.entry(node).or_insert_with(|| planned.name.clone());
        planned.name = numbered_name(base, ItemKind::Folder, tried);
    }

    pub fn upload_finished(&mut self, node: u32, ok: bool) {
        if !self.uploading.remove(&node) {
            return;
        }
        if ok {
            self.files_done += 1;
        } else {
            let shown = self.shown(node);
            self.run_skips
                .push((shown, SkipReason::Unsupported("The upload failed".into())));
        }
        self.progress_due = true;
    }

    /// The driver saw the archive's identity (again). A different version
    /// fails the run: what lands must be what was previewed.
    pub fn identity_seen(&mut self, identity: &ArchiveIdentity) {
        if *identity != self.identity {
            self.fail(FailReason::Changed);
        }
    }

    pub fn run_failed(&mut self, reason: FailReason) {
        self.fail(reason);
    }

    pub fn supply_password(&mut self, password: ArchivePassword) {
        self.password = Some(password);
    }

    /// Stop. Files whose upload finished stay (A7). The password is wiped
    /// now.
    pub fn cancel(&mut self) {
        if self.stop.is_none() {
            self.stop = Some(ExtractOutcome::Stopped);
        }
        self.password = None;
    }

    fn fail(&mut self, reason: FailReason) {
        if self.stop.is_none() {
            self.stop = Some(ExtractOutcome::Failed(reason));
        }
        self.password = None;
    }

    fn shown(&self, node: u32) -> String {
        let listing = self.session.listing();
        self.plan
            .nodes
            .get(node as usize)
            .and_then(|n| n.entry)
            .and_then(|e| listing.and_then(|l| l.entries.get(e as usize)))
            .map(|e| e.display_path.clone())
            .unwrap_or_else(|| {
                self.plan
                    .nodes
                    .get(node as usize)
                    .map(|n| n.name.clone())
                    .unwrap_or_default()
            })
    }

    fn summary(&self, outcome: ExtractOutcome) -> ExtractSummary {
        let listing = self.session.listing();
        let shown = |entry: u32| {
            listing
                .and_then(|l| l.entries.get(entry as usize))
                .map(|e| e.display_path.clone())
                .unwrap_or_default()
        };
        let mut skipped: Vec<(String, SkipReason)> = self
            .plan
            .skipped
            .iter()
            .map(|(entry, reason)| (shown(*entry), reason.clone()))
            .collect();
        skipped.extend(self.run_skips.iter().cloned());
        ExtractSummary {
            outcome,
            target_name: self.plan.nodes.first().map(|n| n.name.clone()).unwrap_or_default(),
            files_done: self.files_done,
            files_total: self.files_total,
            skipped,
            renamed: self
                .plan
                .renamed
                .iter()
                .map(|(entry, name)| (shown(*entry), name.clone()))
                .collect(),
        }
    }

    fn progress(&self) -> ExtractProgress {
        ExtractProgress {
            files_done: self.files_done,
            files_total: self.files_total,
            bytes_done: self.bytes_done,
            bytes_total: self.plan.totals.bytes,
            current: self.current.as_ref().map(|c| self.shown(c.node)).unwrap_or_default(),
        }
    }

    fn finish(&mut self, outcome: ExtractOutcome) -> ExtractStep {
        self.password = None;
        self.current = None;
        let summary = self.summary(outcome);
        self.finished = Some(summary.clone());
        ExtractStep::Finished(summary)
    }

    pub fn step(&mut self) -> ExtractStep {
        if let Some(summary) = &self.finished {
            return ExtractStep::Finished(summary.clone());
        }
        if let Some(outcome) = self.stop {
            return self.finish(outcome);
        }
        if let Some(node) = self.awaiting {
            return self.create_folder(node);
        }
        if let Some(node) = self.folders.pop_front() {
            self.awaiting = Some(node);
            return self.create_folder(node);
        }
        if self.progress_due {
            self.progress_due = false;
            return ExtractStep::Progress(self.progress());
        }
        if self.current.is_none() {
            if let Some(node) = self.files.pop_front() {
                let entry = self.plan.nodes[node as usize].entry.unwrap_or(0);
                let encrypted = self
                    .session
                    .listing()
                    .and_then(|l| l.entries.get(entry as usize))
                    .is_some_and(|e| e.cipher.is_encrypted());
                self.current = Some(Current::new(node, entry, encrypted));
            } else if let Some(step) = self.after_planned_files() {
                return step;
            } else if !self.uploading.is_empty() {
                return ExtractStep::Waiting;
            } else {
                return self.finish(ExtractOutcome::Done);
            }
        }
        self.step_file()
    }

    fn create_folder(&self, node: u32) -> ExtractStep {
        let planned = &self.plan.nodes[node as usize];
        ExtractStep::CreateFolder {
            node,
            parent: planned.parent,
            name: planned.name.clone(),
        }
    }

    fn step_file(&mut self) -> ExtractStep {
        let Some(current) = self.current.as_mut() else {
            return ExtractStep::Waiting;
        };
        let (node, entry) = (current.node, current.entry);
        let tgz = self
            .session
            .listing()
            .is_some_and(|l| l.format == ArchiveFormat::TarGzip);
        if current.decoder.is_none() && !tgz {
            if current.encrypted && self.password.is_none() {
                return ExtractStep::NeedPassword {
                    entry,
                    wrong: self.ask_wrong,
                };
            }
            match self.session.decoder(entry, self.password.as_ref()) {
                Ok(decoder) => current.decoder = Some(decoder),
                Err(_) => return self.skip_current(SkipReason::Corrupt),
            }
        }
        if !current.began {
            if let Some(decoder) = current.decoder.as_mut() {
                match decoder.open(self.session.source_mut()) {
                    None => {}
                    Some(PieceStep::NeedBytes(range)) => return ExtractStep::NeedBytes(range),
                    Some(PieceStep::WrongPassword) => return self.wrong_password(),
                    Some(PieceStep::Io(_)) => {
                        self.fail(FailReason::Network);
                        return self.step();
                    }
                    Some(_) => return self.skip_current(SkipReason::Corrupt),
                }
            }
            let current = self.current.as_mut().expect("current file");
            current.began = true;
            if let Some(decoder) = current.decoder.as_ref() {
                current.opened_with = decoder.opened_with();
                current.proves_password = decoder.proves_password();
            }
            let planned = &self.plan.nodes[node as usize];
            return ExtractStep::FileBegin {
                node,
                parent: planned.parent,
                name: planned.name.clone(),
                size: planned.size,
            };
        }
        let step = if tgz { self.tgz_next() } else { self.decoder_next() };
        match step {
            PieceStep::Data(bytes) => {
                let complete = self.session.listing().is_some_and(|l| l.complete);
                let total = self.bytes_done + bytes.len() as u64;
                if (complete && total > self.plan.totals.bytes) || total > MAX_EXTRACTION_BYTES {
                    // Headers lie: the running total never passes the
                    // declared total.
                    return self.skip_current(SkipReason::Bomb);
                }
                self.bytes_done = total;
                if let Some(current) = self.current.as_mut() {
                    current.bytes += bytes.len() as u64;
                }
                ExtractStep::FileData { node, bytes }
            }
            PieceStep::Verified => {
                if let Some(current) = self.current.as_ref()
                    && current.encrypted
                    && current.proves_password
                {
                    // Only a check over real data proves the password: an
                    // empty ZipCrypto entry passes under any key that
                    // passes its check byte.
                    self.password_proven = true;
                    if let (Some(tried), Some(password)) = (current.opened_with, self.password.as_mut()) {
                        password.note_proven(tried);
                    }
                }
                self.current = None;
                self.uploading.insert(node);
                self.progress_due = true;
                ExtractStep::FileEnd { node }
            }
            PieceStep::NeedBytes(range) => ExtractStep::NeedBytes(range),
            PieceStep::WrongPassword => self.wrong_password(),
            PieceStep::Corrupt => {
                let encrypted = self.current.as_ref().is_some_and(|c| c.encrypted);
                if encrypted && !self.password_proven && self.retried.insert(node) {
                    // A wrong password that passed the check byte: the
                    // staged bytes are dropped, the person is asked again,
                    // and this entry is read again with the new password.
                    return self.retry_current();
                }
                if tgz {
                    // A damaged gzip stream cannot be read past this point.
                    self.fail(FailReason::Damaged);
                }
                self.skip_current(SkipReason::Corrupt)
            }
            PieceStep::Skipped(reason) => {
                if tgz && reason == SkipReason::Bomb {
                    self.fail(FailReason::Damaged);
                }
                self.skip_current(reason)
            }
            PieceStep::Io(_) => {
                self.fail(FailReason::Network);
                self.step()
            }
        }
    }

    fn decoder_next(&mut self) -> PieceStep {
        let source = self.session.source_mut();
        match self.current.as_mut().and_then(|c| c.decoder.as_mut()) {
            Some(decoder) => decoder.next_piece(source),
            None => PieceStep::Corrupt,
        }
    }

    fn tgz_next(&mut self) -> PieceStep {
        let Some(current) = self.current.as_mut() else {
            return PieceStep::Corrupt;
        };
        let ordinal = match self.session.locator(current.entry) {
            Some(Locator::Tar { ordinal, .. }) => *ordinal,
            // An entry past the listing: the walker already stands at it.
            _ if current.tgz_found => u32::MAX,
            _ => return PieceStep::Corrupt,
        };
        let walker = self
            .tgz
            .get_or_insert_with(|| Box::new(TarWalker::new(GzInput::new(None))));
        let source = self.session.source_mut();
        match tgz_piece(walker, ordinal, &mut current.tgz_found, source) {
            Ok(step) => step,
            Err(halt) => halt_piece(halt),
        }
    }

    fn wrong_password(&mut self) -> ExtractStep {
        let Some(current) = self.current.as_mut() else {
            return ExtractStep::Waiting;
        };
        current.decoder = None;
        if self.password_proven {
            // The password opened other entries: this one uses another.
            return self.skip_current(SkipReason::OtherPassword);
        }
        let entry = current.entry;
        self.password = None;
        self.ask_wrong = true;
        ExtractStep::NeedPassword { entry, wrong: true }
    }

    /// Drop the current entry's attempt (the driver deletes what it
    /// staged on `FileSkipped`, which is not counted as a skip), forget
    /// the password, and queue the entry to be read first once a new
    /// password arrives.
    fn retry_current(&mut self) -> ExtractStep {
        let Some(current) = self.current.take() else {
            return ExtractStep::Waiting;
        };
        self.bytes_done = self.bytes_done.saturating_sub(current.bytes);
        self.files.push_front(current.node);
        self.password = None;
        self.ask_wrong = true;
        ExtractStep::FileSkipped {
            node: current.node,
            reason: SkipReason::Corrupt,
        }
    }

    fn skip_current(&mut self, reason: SkipReason) -> ExtractStep {
        let Some(current) = self.current.take() else {
            return ExtractStep::Waiting;
        };
        let shown = self.shown(current.node);
        self.run_skips.push((shown, reason.clone()));
        self.progress_due = true;
        ExtractStep::FileSkipped {
            node: current.node,
            reason,
        }
    }

    /// After the planned files: a tgz runs its stream to the end, which
    /// checks every gzip trailer and, when the listing was incomplete,
    /// extracts the entries past it. `None` when there is nothing left.
    fn after_planned_files(&mut self) -> Option<ExtractStep> {
        let listing = self.session.listing()?;
        if listing.format != ArchiveFormat::TarGzip || self.tail_checked || !self.plan.whole_archive {
            return None;
        }
        let complete = listing.complete;
        if !complete && self.tail.is_none() {
            self.tail = Some(self.tail_names());
        }
        loop {
            if let Some(node) = self.tail.as_mut().and_then(|t| t.pending.take()) {
                let planned = &self.plan.nodes[node as usize];
                self.current = Some(Current {
                    tgz_found: true,
                    began: true,
                    ..Current::new(node, u32::MAX, false)
                });
                return Some(ExtractStep::FileBegin {
                    node,
                    parent: planned.parent,
                    name: planned.name.clone(),
                    size: planned.size,
                });
            }
            let walker = self
                .tgz
                .get_or_insert_with(|| Box::new(TarWalker::new(GzInput::new(None))));
            let source = self.session.source_mut();
            match walker.next_entry(source).and_then(|event| match event {
                // The tar's end block is not the gzip stream's end: read
                // on, so every member's trailer is checked.
                TarEvent::End => drain(&mut walker.input, source).map(|()| TarEvent::End),
                entry => Ok(entry),
            }) {
                Ok(TarEvent::End) => {
                    self.tail_checked = true;
                    return None;
                }
                Ok(TarEvent::Entry(header)) => {
                    if complete || self.is_listed(header.ordinal) {
                        continue;
                    }
                    if let Some(step) = self.plan_tail_entry(header) {
                        return Some(step);
                    }
                }
                Err(Halt::Need(range)) => return Some(ExtractStep::NeedBytes(range)),
                Err(Halt::Io(_)) => {
                    self.fail(FailReason::Network);
                    return Some(self.step());
                }
                Err(_) => {
                    self.fail(FailReason::Damaged);
                    return Some(self.step());
                }
            }
        }
    }

    fn is_listed(&self, ordinal: u32) -> bool {
        ordinal < self.session.tar_ordinals_listed()
    }

    fn tail_names(&self) -> Tail {
        let mut taken: HashMap<u32, TakenNames> = HashMap::new();
        let mut folders = HashMap::new();
        for node in &self.plan.nodes {
            if let Some(parent) = node.parent {
                taken.entry(parent).or_default().insert(&node.name);
                if node.kind == NodeKind::Folder {
                    folders.insert((parent, node.source_name.clone()), node.id);
                }
            }
        }
        Tail {
            taken,
            folders,
            pending: None,
        }
    }

    /// Plan one entry the listing did not reach, with the planner's rules.
    fn plan_tail_entry(&mut self, header: TarHeader) -> Option<ExtractStep> {
        let (entry, _) = tar_entry(&header);
        let reason = match (&entry.skip, &entry.path) {
            (Some(reason), _) => Some(reason.clone()),
            (None, None) => Some(SkipReason::UnusableName),
            (None, Some(_)) if entry.size > self.session.platform().max_entry_bytes() => Some(SkipReason::TooLarge),
            (None, Some(_)) if self.plan.nodes.len() > MAX_ENTRIES => {
                Some(SkipReason::Unsupported("More than 100,000 items".into()))
            }
            _ => None,
        };
        if let Some(reason) = reason {
            self.run_skips.push((entry.display_path.clone(), reason));
            return None;
        }
        let path = entry.path?;
        let PlanTarget::Folder(root) = self.plan.target else {
            return None;
        };
        let (last, parents) = path.components.split_last()?;
        let mut parent = root;
        let mut new_folders = Vec::new();
        for component in parents {
            parent = self.tail_node(parent, component, NodeKind::Folder, 0, &mut new_folders);
        }
        let node = if entry.kind == EntryKind::Folder {
            self.tail_node(parent, last, NodeKind::Folder, 0, &mut new_folders);
            None
        } else {
            self.files_total += 1;
            Some(self.tail_node(parent, last, NodeKind::File, header.size, &mut new_folders))
        };
        self.folders.extend(new_folders);
        if let Some(node) = node
            && let Some(tail) = self.tail.as_mut()
        {
            tail.pending = Some(node);
        }
        self.awaiting = self.folders.pop_front();
        if let Some(folder) = self.awaiting {
            return Some(self.create_folder(folder));
        }
        self.after_planned_files()
    }

    fn tail_node(&mut self, parent: u32, name: &str, kind: NodeKind, size: u64, new_folders: &mut Vec<u32>) -> u32 {
        let tail = self.tail.as_mut().expect("tail naming state");
        if kind == NodeKind::Folder
            && let Some(&id) = tail.folders.get(&(parent, name.to_string()))
        {
            return id;
        }
        let taken = tail.taken.entry(parent).or_default();
        let item = if kind == NodeKind::Folder {
            ItemKind::Folder
        } else {
            ItemKind::File
        };
        let final_name = if taken.contains(name) {
            numbered_name(name, item, taken)
        } else {
            name.to_string()
        };
        taken.insert(&final_name);
        let id = self.plan.nodes.len() as u32;
        self.plan.nodes.push(PlannedNode {
            id,
            parent: Some(parent),
            name: final_name,
            source_name: name.to_string(),
            kind,
            entry: None,
            size,
        });
        if kind == NodeKind::Folder {
            tail.folders.insert((parent, name.to_string()), id);
            new_folders.push(id);
        }
        id
    }
}

/// Read a gzip stream to its end; `Ok` once every trailer matched.
fn drain<S: ByteSource + ?Sized>(input: &mut GzInput, source: &mut S) -> Result<(), Halt> {
    loop {
        match input.skip(source, u64::MAX) {
            Ok(_) => {}
            Err(Halt::Refused(super::model::ArchiveRefusal::Truncated)) if input.ended() => return Ok(()),
            Err(halt) => return Err(halt),
        }
    }
}

fn halt_piece(halt: Halt) -> PieceStep {
    match halt {
        Halt::Need(range) => PieceStep::NeedBytes(range),
        Halt::Io(e) => PieceStep::Io(e),
        Halt::Refused(super::model::ArchiveRefusal::Bomb) => PieceStep::Skipped(SkipReason::Bomb),
        Halt::Refused(_) | Halt::Limit => PieceStep::Corrupt,
    }
}
