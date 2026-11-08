//! The archive words, records and in-memory listing for iOS (and later
//! Android): archives design §5.1, §5.3, §9. Every function forwards to
//! `beebeeb_core::archives`; no rule lives here. The records mirror core's
//! preview model, progress, summary and words field for field, so the
//! native archive service returns them unchanged. An unknown key or platform
//! string is `CryptoError::InvalidInput`, never a pass.

use std::io::Cursor;

use beebeeb_core::archives as rules;

use super::CryptoError;

fn invalid(detail: &str) -> CryptoError {
    CryptoError::InvalidInput { detail: detail.into() }
}

fn parse_platform(platform: &str) -> Result<rules::ArchivePlatform, CryptoError> {
    rules::ArchivePlatform::parse(platform).ok_or_else(|| invalid("unknown archive platform"))
}

// ── Words ──────────────────────────────────────────────────────────────────

/// One argument of a word, already formatted (`files` = `"1,234"`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveTextArg {
    pub name: String,
    pub value: String,
}

/// Core's words: a stable key, the English text, and the unsubstituted
/// arguments for an i18n layer.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveText {
    pub key: String,
    pub text: String,
    pub args: Vec<ArchiveTextArg>,
}

impl From<rules::ArchiveText> for ArchiveText {
    fn from(t: rules::ArchiveText) -> Self {
        Self {
            key: t.key.to_string(),
            text: t.text,
            args: t
                .args
                .into_iter()
                .map(|(name, value)| ArchiveTextArg { name, value })
                .collect(),
        }
    }
}

/// Core's words for `key` (`"extract_done"`, ...) with `args`.
#[uniffi::export]
pub fn archive_text(key: String, args: Vec<ArchiveTextArg>) -> Result<ArchiveText, CryptoError> {
    let key = rules::ArchiveKey::parse(&key).ok_or_else(|| invalid("unknown archive word"))?;
    let pairs: Vec<(&str, &str)> = args.iter().map(|a| (a.name.as_str(), a.value.as_str())).collect();
    Ok(rules::archive_text(key, &pairs).into())
}

/// A count as the archive words show it (`1,234`).
#[uniffi::export]
pub fn archive_count_label(n: u64) -> String {
    rules::words::count_label(n)
}

/// A size as the archive words show it (`3.4 MB`).
#[uniffi::export]
pub fn archive_size_label(bytes: u64) -> String {
    rules::words::size_label(bytes)
}

// ── The listing ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    Tgz,
    Gz,
}

impl From<rules::ArchiveFormat> for ArchiveFormat {
    fn from(f: rules::ArchiveFormat) -> Self {
        match f {
            rules::ArchiveFormat::Zip => Self::Zip,
            rules::ArchiveFormat::Tar => Self::Tar,
            rules::ArchiveFormat::TarGzip => Self::Tgz,
            rules::ArchiveFormat::Gzip => Self::Gz,
        }
    }
}

/// Why a whole archive is refused; `format` is the binding name of a
/// foreign one (`"rar"`, `"7z"`, `"xz"`, `"zstd"`, `"bzip2"`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveRefusal {
    NotAnArchive,
    Foreign { format: String },
    SelfExtracting,
    Spanned,
    StrongEncryption,
    Damaged,
    Truncated,
    TooMany,
    Bomb,
}

impl From<rules::ArchiveRefusal> for ArchiveRefusal {
    fn from(r: rules::ArchiveRefusal) -> Self {
        match r {
            rules::ArchiveRefusal::NotAnArchive => Self::NotAnArchive,
            rules::ArchiveRefusal::Foreign(format) => Self::Foreign {
                format: format.as_str().to_string(),
            },
            rules::ArchiveRefusal::SelfExtracting => Self::SelfExtracting,
            rules::ArchiveRefusal::Spanned => Self::Spanned,
            rules::ArchiveRefusal::StrongEncryption => Self::StrongEncryption,
            rules::ArchiveRefusal::Damaged => Self::Damaged,
            rules::ArchiveRefusal::Truncated => Self::Truncated,
            rules::ArchiveRefusal::TooMany => Self::TooMany,
            rules::ArchiveRefusal::Bomb => Self::Bomb,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveEntryKind {
    File,
    Folder,
    Symlink,
    HardLink,
    Device,
    Other,
}

impl From<rules::EntryKind> for ArchiveEntryKind {
    fn from(k: rules::EntryKind) -> Self {
        match k {
            rules::EntryKind::File => Self::File,
            rules::EntryKind::Folder => Self::Folder,
            rules::EntryKind::Symlink => Self::Symlink,
            rules::EntryKind::HardLink => Self::HardLink,
            rules::EntryKind::Device => Self::Device,
            rules::EntryKind::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveCipher {
    None,
    ZipCrypto,
    /// WinZip AES: 128, 192 or 256 bits; AE-1 or AE-2.
    Aes {
        bits: u16,
        ae: u8,
    },
}

impl From<rules::EntryCipher> for ArchiveCipher {
    fn from(c: rules::EntryCipher) -> Self {
        match c {
            rules::EntryCipher::None => Self::None,
            rules::EntryCipher::ZipCrypto => Self::ZipCrypto,
            rules::EntryCipher::Aes { bits, ae } => Self::Aes { bits, ae },
        }
    }
}

/// When an entry was last modified: an absolute time, or a zone-less DOS
/// time shown as wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveTime {
    Utc {
        unix_ms: i64,
    },
    Local {
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    },
}

impl From<rules::ArchiveTime> for ArchiveTime {
    fn from(t: rules::ArchiveTime) -> Self {
        match t {
            rules::ArchiveTime::Utc { unix_ms } => Self::Utc { unix_ms },
            rules::ArchiveTime::Local {
                year,
                month,
                day,
                hour,
                minute,
                second,
            } => Self::Local {
                year,
                month,
                day,
                hour,
                minute,
                second,
            },
        }
    }
}

/// Why an entry is listed but not extracted.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveSkipReason {
    Link,
    Device,
    OutsideFolder,
    UnusableName,
    Method { name: String },
    TooLarge,
    Bomb,
    MacResource,
    Corrupt,
    OtherPassword,
    Unsupported { what: String },
}

impl From<rules::SkipReason> for ArchiveSkipReason {
    fn from(r: rules::SkipReason) -> Self {
        match r {
            rules::SkipReason::Link => Self::Link,
            rules::SkipReason::Device => Self::Device,
            rules::SkipReason::OutsideFolder => Self::OutsideFolder,
            rules::SkipReason::UnusableName => Self::UnusableName,
            rules::SkipReason::Method(name) => Self::Method { name },
            rules::SkipReason::TooLarge => Self::TooLarge,
            rules::SkipReason::Bomb => Self::Bomb,
            rules::SkipReason::MacResource => Self::MacResource,
            rules::SkipReason::Corrupt => Self::Corrupt,
            rules::SkipReason::OtherPassword => Self::OtherPassword,
            rules::SkipReason::Unsupported(what) => Self::Unsupported { what },
        }
    }
}

impl From<ArchiveSkipReason> for rules::SkipReason {
    fn from(r: ArchiveSkipReason) -> Self {
        match r {
            ArchiveSkipReason::Link => Self::Link,
            ArchiveSkipReason::Device => Self::Device,
            ArchiveSkipReason::OutsideFolder => Self::OutsideFolder,
            ArchiveSkipReason::UnusableName => Self::UnusableName,
            ArchiveSkipReason::Method { name } => Self::Method(name),
            ArchiveSkipReason::TooLarge => Self::TooLarge,
            ArchiveSkipReason::Bomb => Self::Bomb,
            ArchiveSkipReason::MacResource => Self::MacResource,
            ArchiveSkipReason::Corrupt => Self::Corrupt,
            ArchiveSkipReason::OtherPassword => Self::OtherPassword,
            ArchiveSkipReason::Unsupported { what } => Self::Unsupported(what),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveEntry {
    pub index: u32,
    /// The decoded name as shown, control characters made visible.
    pub display_path: String,
    /// The path extraction writes; `None` when the entry is skipped for its
    /// name.
    pub path: Option<String>,
    pub kind: ArchiveEntryKind,
    pub size: u64,
    pub compressed_size: u64,
    pub cipher: ArchiveCipher,
    pub modified: Option<ArchiveTime>,
    pub skip: Option<ArchiveSkipReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveTotals {
    pub files: u32,
    pub folders: u32,
    pub bytes: u64,
    pub compressed_bytes: u64,
    pub skipped: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveProtection {
    None,
    Some,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveListing {
    pub format: ArchiveFormat,
    pub entries: Vec<ArchiveEntry>,
    pub totals: ArchiveTotals,
    pub protection: ArchiveProtection,
    pub uses_zipcrypto: bool,
    /// `false` when a tgz or gz listing stopped at the platform's scan limit.
    pub complete: bool,
}

impl From<&rules::ArchiveListing> for ArchiveListing {
    fn from(l: &rules::ArchiveListing) -> Self {
        Self {
            format: l.format.into(),
            entries: l
                .entries
                .iter()
                .map(|e| ArchiveEntry {
                    index: e.index,
                    display_path: e.display_path.clone(),
                    path: e.path.as_ref().map(|p| p.joined()),
                    kind: e.kind.into(),
                    size: e.size,
                    compressed_size: e.compressed_size,
                    cipher: e.cipher.into(),
                    modified: e.modified.map(Into::into),
                    skip: e.skip.clone().map(Into::into),
                })
                .collect(),
            totals: ArchiveTotals {
                files: l.totals.files,
                folders: l.totals.folders,
                bytes: l.totals.bytes,
                compressed_bytes: l.totals.compressed_bytes,
                skipped: l.totals.skipped,
            },
            protection: match l.protection {
                rules::Protection::None => ArchiveProtection::None,
                rules::Protection::Some => ArchiveProtection::Some,
                rules::Protection::All => ArchiveProtection::All,
            },
            uses_zipcrypto: l.uses_zipcrypto,
            complete: l.complete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveListResult {
    Listed { listing: ArchiveListing },
    Refused { refusal: ArchiveRefusal, text: ArchiveText },
}

/// List an archive already in memory (the vectors, a small attachment) on
/// `platform` (`"native"`, `"browser"` or `"mobile_app"`). A large archive
/// is listed by the archive service's range reads, never through this.
#[uniffi::export]
pub fn archive_list(bytes: Vec<u8>, platform: String) -> Result<ArchiveListResult, CryptoError> {
    let platform = parse_platform(&platform)?;
    let source =
        rules::ReadSeekSource::new(Cursor::new(bytes)).map_err(|e| CryptoError::Io { detail: e.to_string() })?;
    let mut session = rules::ArchiveSession::open(source, platform);
    match session.step() {
        rules::SessionStep::Listed => {
            let listing = session.listing().ok_or_else(|| invalid("the archive is not listed"))?;
            Ok(ArchiveListResult::Listed {
                listing: listing.into(),
            })
        }
        rules::SessionStep::Refused(refusal) => Ok(ArchiveListResult::Refused {
            refusal: refusal.into(),
            text: rules::preview::refusal_text(refusal).into(),
        }),
        rules::SessionStep::Io(detail) => Err(CryptoError::Io { detail }),
        rules::SessionStep::NeedBytes(_) => Err(CryptoError::Io {
            detail: "an in-memory archive asked for bytes".into(),
        }),
    }
}

// ── The preview model, progress and summary ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArchivePreviewState {
    Reading,
    Listed,
    NeedsPassword { wrong: bool },
    Extracting,
    Finished,
    Refused,
}

impl From<rules::PreviewState> for ArchivePreviewState {
    fn from(s: rules::PreviewState) -> Self {
        match s {
            rules::PreviewState::Reading => Self::Reading,
            rules::PreviewState::Listed => Self::Listed,
            rules::PreviewState::NeedsPassword { wrong } => Self::NeedsPassword { wrong },
            rules::PreviewState::Extracting => Self::Extracting,
            rules::PreviewState::Finished => Self::Finished,
            rules::PreviewState::Refused => Self::Refused,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveActionKind {
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

impl From<rules::ActionKind> for ArchiveActionKind {
    fn from(k: rules::ActionKind) -> Self {
        match k {
            rules::ActionKind::Extract => Self::Extract,
            rules::ActionKind::ExtractTo => Self::ExtractTo,
            rules::ActionKind::ExtractSelected => Self::ExtractSelected,
            rules::ActionKind::Download => Self::Download,
            rules::ActionKind::Open => Self::Open,
            rules::ActionKind::Stop => Self::Stop,
            rules::ActionKind::OpenFolder => Self::OpenFolder,
            rules::ActionKind::MoveToTrash => Self::MoveToTrash,
            rules::ActionKind::Cancel => Self::Cancel,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchivePreviewAction {
    pub kind: ArchiveActionKind,
    pub label: ArchiveText,
    pub enabled: bool,
}

impl From<rules::PreviewAction> for ArchivePreviewAction {
    fn from(a: rules::PreviewAction) -> Self {
        Self {
            kind: a.kind.into(),
            label: a.label.into(),
            enabled: a.enabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchivePreviewRow {
    pub name: String,
    pub kind: ArchiveEntryKind,
    /// The listing entry it shows (`None` for a folder made of other
    /// entries' paths, or a summary row).
    pub entry: Option<u32>,
    pub size_label: Option<String>,
    pub modified: Option<ArchiveTime>,
    /// Protected by a password.
    pub locked: bool,
    pub note: Option<ArchiveText>,
    pub actions: Vec<ArchiveActionKind>,
}

/// What the archive screen shows: core decides every word, row and action.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchivePreviewModel {
    pub state: ArchivePreviewState,
    pub title: String,
    pub kind_label: Option<ArchiveText>,
    pub summary: Option<ArchiveText>,
    pub notices: Vec<ArchiveText>,
    pub path: Vec<String>,
    pub rows: Vec<ArchivePreviewRow>,
    pub actions: Vec<ArchivePreviewAction>,
    pub selection_actions: Vec<ArchivePreviewAction>,
}

impl From<rules::ArchivePreviewModel> for ArchivePreviewModel {
    fn from(m: rules::ArchivePreviewModel) -> Self {
        Self {
            state: m.state.into(),
            title: m.title,
            kind_label: m.kind_label.map(Into::into),
            summary: m.summary.map(Into::into),
            notices: m.notices.into_iter().map(Into::into).collect(),
            path: m.path,
            rows: m
                .rows
                .into_iter()
                .map(|r| ArchivePreviewRow {
                    name: r.name,
                    kind: r.kind.into(),
                    entry: r.entry,
                    size_label: r.size_label,
                    modified: r.modified.map(Into::into),
                    locked: r.locked,
                    note: r.note.map(Into::into),
                    actions: r.actions.into_iter().map(Into::into).collect(),
                })
                .collect(),
            actions: m.actions.into_iter().map(Into::into).collect(),
            selection_actions: m.selection_actions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
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

impl From<rules::ExtractProgress> for ExtractProgress {
    fn from(p: rules::ExtractProgress) -> Self {
        Self {
            files_done: p.files_done,
            files_total: p.files_total,
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            current: p.current,
        }
    }
}

impl From<ExtractProgress> for rules::ExtractProgress {
    fn from(p: ExtractProgress) -> Self {
        Self {
            files_done: p.files_done,
            files_total: p.files_total,
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            current: p.current,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ExtractFailReason {
    StorageFull,
    Network,
    Damaged,
    Changed,
    AccountBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ExtractOutcome {
    Done,
    Stopped,
    Failed { reason: ExtractFailReason },
}

impl From<rules::ExtractOutcome> for ExtractOutcome {
    fn from(o: rules::ExtractOutcome) -> Self {
        let reason = |r: rules::FailReason| match r {
            rules::FailReason::StorageFull => ExtractFailReason::StorageFull,
            rules::FailReason::Network => ExtractFailReason::Network,
            rules::FailReason::Damaged => ExtractFailReason::Damaged,
            rules::FailReason::Changed => ExtractFailReason::Changed,
            rules::FailReason::AccountBlocked => ExtractFailReason::AccountBlocked,
        };
        match o {
            rules::ExtractOutcome::Done => Self::Done,
            rules::ExtractOutcome::Stopped => Self::Stopped,
            rules::ExtractOutcome::Failed(r) => Self::Failed { reason: reason(r) },
        }
    }
}

impl From<ExtractOutcome> for rules::ExtractOutcome {
    fn from(o: ExtractOutcome) -> Self {
        let reason = |r: ExtractFailReason| match r {
            ExtractFailReason::StorageFull => rules::FailReason::StorageFull,
            ExtractFailReason::Network => rules::FailReason::Network,
            ExtractFailReason::Damaged => rules::FailReason::Damaged,
            ExtractFailReason::Changed => rules::FailReason::Changed,
            ExtractFailReason::AccountBlocked => rules::FailReason::AccountBlocked,
        };
        match o {
            ExtractOutcome::Done => Self::Done,
            ExtractOutcome::Stopped => Self::Stopped,
            ExtractOutcome::Failed { reason: r } => Self::Failed(reason(r)),
        }
    }
}

/// An entry not extracted (its shown path), and why.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveSkippedEntry {
    pub path: String,
    pub reason: ArchiveSkipReason,
}

/// An entry saved under another name.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveRenamedEntry {
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExtractSummary {
    pub outcome: ExtractOutcome,
    /// The destination folder's (or the one file's) final name.
    pub target_name: String,
    /// Files whose upload finished: exactly what is in the folder.
    pub files_done: u32,
    pub files_total: u32,
    pub skipped: Vec<ArchiveSkippedEntry>,
    pub renamed: Vec<ArchiveRenamedEntry>,
}

impl From<rules::ExtractSummary> for ExtractSummary {
    fn from(s: rules::ExtractSummary) -> Self {
        Self {
            outcome: s.outcome.into(),
            target_name: s.target_name,
            files_done: s.files_done,
            files_total: s.files_total,
            skipped: s
                .skipped
                .into_iter()
                .map(|(path, reason)| ArchiveSkippedEntry {
                    path,
                    reason: reason.into(),
                })
                .collect(),
            renamed: s
                .renamed
                .into_iter()
                .map(|(path, name)| ArchiveRenamedEntry { path, name })
                .collect(),
        }
    }
}

impl From<ExtractSummary> for rules::ExtractSummary {
    fn from(s: ExtractSummary) -> Self {
        Self {
            outcome: s.outcome.into(),
            target_name: s.target_name,
            files_done: s.files_done,
            files_total: s.files_total,
            skipped: s.skipped.into_iter().map(|e| (e.path, e.reason.into())).collect(),
            renamed: s.renamed.into_iter().map(|e| (e.path, e.name)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use beebeeb_core::archives as core;

    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../test-vectors/archives/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture")
    }

    /// Progress and a summary cross to Swift and back unchanged; the preview
    /// model, the listing and the words mirror core's field for field.
    #[test]
    fn archives_records_round_trip() {
        let progress = core::ExtractProgress {
            files_done: 3,
            files_total: 9,
            bytes_done: (1 << 53) + 1,
            bytes_total: u64::MAX,
            current: "docs/readme.txt".into(),
        };
        assert_eq!(
            core::ExtractProgress::from(ExtractProgress::from(progress.clone())),
            progress
        );

        let summary = core::ExtractSummary {
            outcome: core::ExtractOutcome::Failed(core::FailReason::StorageFull),
            target_name: "plain (2)".into(),
            files_done: 2,
            files_total: 5,
            skipped: vec![
                ("a.bin".into(), core::SkipReason::Method("bzip2".into())),
                ("odd".into(), core::SkipReason::Unsupported("Unknown entry type".into())),
                ("../x".into(), core::SkipReason::OutsideFolder),
            ],
            renamed: vec![("Report.txt".into(), "Report (2).txt".into())],
        };
        assert_eq!(
            core::ExtractSummary::from(ExtractSummary::from(summary.clone())),
            summary
        );

        let args = vec![
            ArchiveTextArg {
                name: "files".into(),
                value: "5".into(),
            },
            ArchiveTextArg {
                name: "folder".into(),
                value: "plain (2)".into(),
            },
        ];
        let text = archive_text("extract_done".into(), args).expect("a known key");
        let want = core::archive_text(
            core::ArchiveKey::ExtractDone,
            &[("files", "5"), ("folder", "plain (2)")],
        );
        assert_eq!((text.key.as_str(), text.text.as_str()), (want.key, want.text.as_str()));
        assert_eq!(text.args.len(), 2);
        assert!(archive_text("archive_nope".into(), Vec::new()).is_err());
        assert_eq!(archive_count_label(1_234_567), "1,234,567");
        assert_eq!(archive_size_label(1_500_000), "1.5 MB");

        let ArchiveListResult::Listed { listing } =
            archive_list(fixture("plain.zip"), "mobile_app".into()).expect("a known platform")
        else {
            panic!("plain.zip lists");
        };
        assert_eq!(listing.format, ArchiveFormat::Zip);
        assert_eq!(listing.entries.len(), 8);
        assert_eq!(listing.entries[1].path.as_deref(), Some("docs/readme.txt"));
        assert_eq!(listing.totals.files, 5);
        let ArchiveListResult::Refused { refusal, text } =
            archive_list(fixture("archive.rar"), "mobile_app".into()).expect("a known platform")
        else {
            panic!("archive.rar is refused");
        };
        assert_eq!(refusal, ArchiveRefusal::Foreign { format: "rar".into() });
        assert_eq!(text.key, "refuse_foreign");
        assert!(archive_list(Vec::new(), "desktop".into()).is_err());

        let core_listing = {
            let source = core::ReadSeekSource::new(std::io::Cursor::new(fixture("plain.zip"))).expect("source");
            let mut session = core::ArchiveSession::open(source, core::ArchivePlatform::MobileApp);
            assert_eq!(session.step(), core::SessionStep::Listed);
            session.listing().expect("listed").clone()
        };
        let model = core::archive_preview(&core::PreviewInput {
            archive_name: "plain.zip",
            listing: core::ListingState::Listed(&core_listing),
            folder: &[],
            selection: &[],
            platform: core::ArchivePlatform::MobileApp,
            destination: core::DestinationKind::NextTo,
            password: None,
            progress: Some(&progress),
            summary: None,
            plan: None,
        });
        let record = ArchivePreviewModel::from(model.clone());
        assert_eq!(record.state, ArchivePreviewState::Extracting);
        assert_eq!(
            record.summary.as_ref().map(|t| t.text.clone()),
            model.summary.map(|t| t.text)
        );
        assert_eq!(record.notices.len(), model.notices.len());
        assert_eq!(record.actions[0].kind, ArchiveActionKind::Stop);
    }
}
