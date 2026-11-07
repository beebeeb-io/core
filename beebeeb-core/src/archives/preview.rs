//! The archive preview screen model (spec §5.3): core decides what the
//! screen shows, which actions it offers and every word; the app decides
//! how it looks. One folder of the archive at a time (`path` is the
//! breadcrumb).

use serde::Serialize;

use super::detect::ArchiveFormat;
use super::extract::{ExtractOutcome, ExtractProgress, ExtractSummary, FailReason};
use super::model::{ArchiveEntry, ArchiveListing, ArchiveRefusal, ArchiveTime, EntryKind, Protection, SkipReason};
use super::plan::ExtractionPlan;
use super::platform::ArchivePlatform;
use super::words::{ArchiveKey, ArchiveText, archive_text, count_label, size_label};
use crate::media::is_previewable_by_extension_for;

/// Where the listing is.
#[derive(Debug, Clone, Copy)]
pub enum ListingState<'a> {
    Reading,
    Listed(&'a ArchiveListing),
    Refused(ArchiveRefusal),
}

/// Where Extract writes: next to the archive, or (under Backups or in a
/// folder the person cannot add to, A8) a folder they choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestinationKind {
    NextTo,
    ChooseFolder,
}

impl DestinationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            DestinationKind::NextTo => "next_to",
            DestinationKind::ChooseFolder => "choose_folder",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [DestinationKind::NextTo, DestinationKind::ChooseFolder]
            .into_iter()
            .find(|kind| kind.as_str() == text)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PreviewInput<'a> {
    pub archive_name: &'a str,
    pub listing: ListingState<'a>,
    /// The archive folder being shown, as path components.
    pub folder: &'a [String],
    /// Selected paths, as the listing shows them.
    pub selection: &'a [String],
    pub platform: ArchivePlatform,
    pub destination: DestinationKind,
    /// `Some(wrong)` while a password is asked for.
    pub password: Option<bool>,
    pub progress: Option<&'a ExtractProgress>,
    pub summary: Option<&'a ExtractSummary>,
    pub plan: Option<&'a ExtractionPlan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Extract,
    ExtractTo,
    ExtractSelected,
    Download,
    Open,
    Stop,
    OpenFolder,
    MoveToTrash,
    Cancel,
}

impl ActionKind {
    /// The binding string (the same as its serde name).
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionKind::Extract => "extract",
            ActionKind::ExtractTo => "extract_to",
            ActionKind::ExtractSelected => "extract_selected",
            ActionKind::Download => "download",
            ActionKind::Open => "open",
            ActionKind::Stop => "stop",
            ActionKind::OpenFolder => "open_folder",
            ActionKind::MoveToTrash => "move_to_trash",
            ActionKind::Cancel => "cancel",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewAction {
    pub kind: ActionKind,
    pub label: ArchiveText,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRow {
    pub name: String,
    pub kind: EntryKind,
    /// The listing entry this row shows (`None` for a summary row).
    pub entry: Option<u32>,
    pub size_label: Option<String>,
    pub modified: Option<ArchiveTime>,
    /// The entry's contents are protected by a password.
    pub locked: bool,
    /// Why it will be skipped, or the name it will be saved as.
    pub note: Option<ArchiveText>,
    pub actions: Vec<ActionKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreviewState {
    Reading,
    Listed,
    NeedsPassword { wrong: bool },
    Extracting,
    Finished,
    Refused,
}

impl PreviewState {
    /// The binding string (`wrong` of `NeedsPassword` is separate).
    pub const fn as_str(self) -> &'static str {
        match self {
            PreviewState::Reading => "reading",
            PreviewState::Listed => "listed",
            PreviewState::NeedsPassword { .. } => "needs_password",
            PreviewState::Extracting => "extracting",
            PreviewState::Finished => "finished",
            PreviewState::Refused => "refused",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePreviewModel {
    pub state: PreviewState,
    pub title: String,
    pub kind_label: Option<ArchiveText>,
    pub summary: Option<ArchiveText>,
    pub notices: Vec<ArchiveText>,
    pub path: Vec<String>,
    pub rows: Vec<PreviewRow>,
    pub actions: Vec<PreviewAction>,
    pub selection_actions: Vec<PreviewAction>,
}

fn action(kind: ActionKind, enabled: bool) -> PreviewAction {
    let key = match kind {
        ActionKind::Extract => ArchiveKey::ActionExtract,
        ActionKind::ExtractTo => ArchiveKey::ActionExtractTo,
        ActionKind::ExtractSelected => ArchiveKey::ActionExtractSelected,
        ActionKind::Download => ArchiveKey::ActionDownload,
        ActionKind::Open => ArchiveKey::ActionOpen,
        ActionKind::Stop => ArchiveKey::ActionStop,
        ActionKind::OpenFolder => ArchiveKey::ActionOpenFolder,
        ActionKind::MoveToTrash => ArchiveKey::ActionMoveToTrash,
        ActionKind::Cancel => ArchiveKey::ActionCancel,
    };
    PreviewAction {
        kind,
        label: archive_text(key, &[]),
        enabled,
    }
}

/// The words for a refused archive.
pub fn refusal_text(refusal: ArchiveRefusal) -> ArchiveText {
    match refusal {
        ArchiveRefusal::NotAnArchive => archive_text(ArchiveKey::RefuseNotArchive, &[]),
        ArchiveRefusal::Foreign(format) => {
            archive_text(ArchiveKey::RefuseForeign, &[("format", format.display_name())])
        }
        ArchiveRefusal::SelfExtracting => archive_text(ArchiveKey::RefuseSfx, &[]),
        ArchiveRefusal::Spanned => archive_text(ArchiveKey::RefuseSpanned, &[]),
        ArchiveRefusal::StrongEncryption => archive_text(ArchiveKey::RefuseStrongEncryption, &[]),
        ArchiveRefusal::Damaged => archive_text(ArchiveKey::RefuseDamaged, &[]),
        ArchiveRefusal::Truncated => archive_text(ArchiveKey::RefuseTruncated, &[]),
        ArchiveRefusal::TooMany => archive_text(ArchiveKey::RefuseTooMany, &[]),
        ArchiveRefusal::Bomb => archive_text(ArchiveKey::RefuseBomb, &[]),
    }
}

/// The note on a skipped entry.
pub fn skip_text(reason: &SkipReason) -> ArchiveText {
    match reason {
        SkipReason::Link => archive_text(ArchiveKey::EntryLink, &[]),
        SkipReason::Device => archive_text(ArchiveKey::EntryDevice, &[]),
        SkipReason::OutsideFolder => archive_text(ArchiveKey::EntryOutside, &[]),
        SkipReason::UnusableName => archive_text(ArchiveKey::EntryBadName, &[]),
        SkipReason::Method(method) => archive_text(ArchiveKey::EntryMethod, &[("method", method)]),
        SkipReason::TooLarge => archive_text(ArchiveKey::EntryTooLarge, &[]),
        SkipReason::Bomb => archive_text(ArchiveKey::EntryBomb, &[]),
        SkipReason::MacResource => archive_text(ArchiveKey::EntryMacResource, &[]),
        SkipReason::Corrupt => archive_text(ArchiveKey::EntryCorrupt, &[]),
        SkipReason::OtherPassword => archive_text(ArchiveKey::EntryOtherPassword, &[]),
        SkipReason::Unsupported(what) => archive_text(ArchiveKey::EntryUnsupported, &[("what", what)]),
    }
}

fn kind_label(format: ArchiveFormat) -> ArchiveText {
    let key = match format {
        ArchiveFormat::Zip => ArchiveKey::ArchiveKindZip,
        ArchiveFormat::Tar => ArchiveKey::ArchiveKindTar,
        ArchiveFormat::TarGzip => ArchiveKey::ArchiveKindTgz,
        ArchiveFormat::Gzip => ArchiveKey::ArchiveKindGz,
    };
    archive_text(key, &[])
}

/// The words for a finished extraction.
pub fn summary_text(summary: &ExtractSummary) -> ArchiveText {
    let (files, done, total) = (
        count_label(u64::from(summary.files_done)),
        count_label(u64::from(summary.files_done)),
        count_label(u64::from(summary.files_total)),
    );
    let folder = summary.target_name.as_str();
    let progress = [("done", done.as_str()), ("total", total.as_str()), ("folder", folder)];
    match summary.outcome {
        ExtractOutcome::Done if summary.skipped.is_empty() => {
            archive_text(ArchiveKey::ExtractDone, &[("files", &files), ("folder", folder)])
        }
        ExtractOutcome::Done => archive_text(
            ArchiveKey::ExtractDoneWithSkips,
            &[
                ("files", &files),
                ("folder", folder),
                ("skipped", &count_label(summary.skipped.len() as u64)),
            ],
        ),
        // A refusal from the account's state has no archive words (spec
        // §9 points at upload words core does not have): the stopped
        // sentence is true for it, and the app's account banner says why.
        ExtractOutcome::Stopped | ExtractOutcome::Failed(FailReason::AccountBlocked) => {
            archive_text(ArchiveKey::ExtractStopped, &progress)
        }
        ExtractOutcome::Failed(FailReason::StorageFull) => {
            archive_text(ArchiveKey::ExtractFailedStorageFull, &progress)
        }
        ExtractOutcome::Failed(FailReason::Network) => archive_text(ArchiveKey::ExtractFailedNetwork, &progress),
        ExtractOutcome::Failed(FailReason::Damaged) => archive_text(ArchiveKey::ExtractFailedDamaged, &progress),
        ExtractOutcome::Failed(FailReason::Changed) => archive_text(ArchiveKey::ExtractFailedChanged, &progress),
    }
}

/// The words for a running extraction.
pub fn progress_text(progress: &ExtractProgress) -> ArchiveText {
    archive_text(
        ArchiveKey::ExtractProgress,
        &[
            ("done", &count_label(u64::from(progress.files_done))),
            ("total", &count_label(u64::from(progress.files_total))),
            ("bytes_done", &size_label(progress.bytes_done)),
            ("bytes_total", &size_label(progress.bytes_total)),
        ],
    )
}

/// Whether Open is offered for an entry: a kind core's preview table
/// shows on this platform, within the platform's in-memory budget.
fn openable(entry: &ArchiveEntry, platform: ArchivePlatform) -> bool {
    entry.kind == EntryKind::File
        && entry.skip.is_none()
        && entry.size <= platform.budget().archive_output_bytes
        && is_previewable_by_extension_for(&entry.display_path, platform.preview_platform())
}

fn row(entry: &ArchiveEntry, name: String, input: &PreviewInput<'_>) -> PreviewRow {
    let renamed = input
        .plan
        .and_then(|plan| plan.renamed.iter().find(|(index, _)| *index == entry.index))
        .map(|(_, saved)| archive_text(ArchiveKey::EntryRenamed, &[("name", saved)]));
    let note = entry.skip.as_ref().map(skip_text).or(renamed);
    let mut actions = Vec::new();
    if entry.kind == EntryKind::File && entry.skip.is_none() {
        actions.push(ActionKind::Download);
        if openable(entry, input.platform) {
            actions.push(ActionKind::Open);
        }
    }
    PreviewRow {
        name,
        kind: entry.kind,
        entry: Some(entry.index),
        size_label: (entry.kind == EntryKind::File).then(|| size_label(entry.size)),
        modified: entry.modified,
        locked: entry.cipher.is_encrypted(),
        note,
        actions,
    }
}

/// The rows of one folder: its folders first, then its files, each by
/// name. An entry with no usable path is shown at the top level under its
/// raw name, with its note.
fn rows(listing: &ArchiveListing, input: &PreviewInput<'_>) -> Vec<PreviewRow> {
    let depth = input.folder.len();
    let mut rows: Vec<PreviewRow> = listing
        .entries
        .iter()
        .filter_map(|entry| match &entry.path {
            Some(path) if path.components.len() == depth + 1 && path.components[..depth] == *input.folder => {
                Some(row(entry, path.components[depth].clone(), input))
            }
            None if depth == 0 => Some(row(entry, entry.display_path.clone(), input)),
            _ => None,
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.kind == EntryKind::Folder)
            .cmp(&(a.kind == EntryKind::Folder))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.entry.cmp(&b.entry))
    });
    rows
}

fn selection_actions(listing: &ArchiveListing, input: &PreviewInput<'_>) -> Vec<PreviewAction> {
    if input.selection.is_empty() {
        return Vec::new();
    }
    let n = count_label(input.selection.len() as u64);
    let mut actions = vec![PreviewAction {
        kind: ActionKind::ExtractSelected,
        label: archive_text(ArchiveKey::ActionExtractSelected, &[("n", &n)]),
        enabled: true,
    }];
    if let [one] = input.selection
        && let Some(entry) = listing.entries.iter().find(|e| &e.display_path == one)
        && entry.kind == EntryKind::File
        && entry.skip.is_none()
    {
        actions.push(action(ActionKind::Download, true));
        if openable(entry, input.platform) {
            actions.push(action(ActionKind::Open, true));
        }
    }
    actions
}

fn listed_notices(listing: &ArchiveListing) -> Vec<ArchiveText> {
    let mut notices = Vec::new();
    match listing.protection {
        Protection::None => {}
        Protection::Some => notices.push(archive_text(ArchiveKey::ArchiveSomeProtected, &[])),
        Protection::All => notices.push(archive_text(ArchiveKey::ArchiveAllProtected, &[])),
    }
    if listing.protection != Protection::None {
        notices.push(archive_text(ArchiveKey::ArchiveNamesNotProtected, &[]));
    }
    if listing.uses_zipcrypto {
        notices.push(archive_text(ArchiveKey::ArchiveZipcryptoWeak, &[]));
    }
    if !listing.complete {
        notices.push(archive_text(ArchiveKey::ArchiveListingIncomplete, &[]));
    }
    notices
}

pub fn archive_preview(input: &PreviewInput<'_>) -> ArchivePreviewModel {
    let mut model = ArchivePreviewModel {
        state: PreviewState::Reading,
        title: input.archive_name.to_string(),
        kind_label: None,
        summary: None,
        notices: Vec::new(),
        path: input.folder.to_vec(),
        rows: Vec::new(),
        actions: Vec::new(),
        selection_actions: Vec::new(),
    };
    let listing = match input.listing {
        ListingState::Reading => {
            model.summary = Some(archive_text(ArchiveKey::ArchiveReading, &[]));
            model.actions = vec![action(ActionKind::Stop, true)];
            return model;
        }
        ListingState::Refused(refusal) => {
            model.state = PreviewState::Refused;
            model.summary = Some(refusal_text(refusal));
            model.actions = vec![action(ActionKind::Download, true)];
            return model;
        }
        ListingState::Listed(listing) => listing,
    };
    model.kind_label = Some(kind_label(listing.format));
    let extract = match input.destination {
        DestinationKind::NextTo => ActionKind::Extract,
        DestinationKind::ChooseFolder => ActionKind::ExtractTo,
    };
    if let Some(summary) = input.summary {
        model.state = PreviewState::Finished;
        model.summary = Some(summary_text(summary));
        if !summary.renamed.is_empty() {
            let n = count_label(summary.renamed.len() as u64);
            model
                .notices
                .push(archive_text(ArchiveKey::ExtractRenamed, &[("n", &n)]));
        }
        model.rows = summary
            .skipped
            .iter()
            .map(|(path, reason)| PreviewRow {
                name: path.clone(),
                kind: EntryKind::File,
                entry: None,
                size_label: None,
                modified: None,
                locked: false,
                note: Some(skip_text(reason)),
                actions: Vec::new(),
            })
            .collect();
        model.actions = match summary.outcome {
            ExtractOutcome::Done => vec![action(ActionKind::OpenFolder, true)],
            _ => vec![
                action(ActionKind::OpenFolder, true),
                action(ActionKind::MoveToTrash, true),
            ],
        };
        return model;
    }
    if let Some(progress) = input.progress {
        model.state = PreviewState::Extracting;
        model.summary = Some(progress_text(progress));
        if input.platform.keep_open_notice() {
            model.notices.push(archive_text(ArchiveKey::ExtractKeepOpen, &[]));
        }
        model.actions = vec![action(ActionKind::Stop, true)];
        return model;
    }
    if let Some(wrong) = input.password {
        model.state = PreviewState::NeedsPassword { wrong };
        model.summary = Some(archive_text(ArchiveKey::PasswordTitle, &[]));
        model
            .notices
            .push(archive_text(ArchiveKey::PasswordBody, &[("name", input.archive_name)]));
        if wrong {
            model.notices.push(archive_text(ArchiveKey::PasswordWrong, &[]));
        }
        model.actions = vec![action(extract, true), action(ActionKind::Cancel, true)];
        return model;
    }
    model.state = PreviewState::Listed;
    model.summary = Some(if listing.entries.is_empty() {
        archive_text(ArchiveKey::ArchiveEmpty, &[])
    } else {
        archive_text(
            ArchiveKey::ArchiveSummary,
            &[
                ("files", &count_label(u64::from(listing.totals.files))),
                ("folders", &count_label(u64::from(listing.totals.folders))),
                ("size", &size_label(listing.totals.bytes)),
            ],
        )
    });
    model.notices = listed_notices(listing);
    if let Some(plan) = input.plan {
        model.notices.extend(plan.notices.iter().cloned());
    }
    model.rows = rows(listing, input);
    model.actions = vec![action(extract, !listing.entries.is_empty())];
    model.selection_actions = selection_actions(listing, input);
    model
}
