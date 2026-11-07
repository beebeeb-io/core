//! Archives for the web (archives design §5, §8): a push session over
//! `SuppliedBytes` that asks for byte ranges, the preview model, the planner
//! and the extraction engine. Every rule is core's; this module converts.
//!
//! Every 64-bit number crosses as a `bigint`, and an absent field is `null`.
//! A password enters as a string and becomes core's zeroizing
//! `ArchivePassword` at once (the JS string itself is the engine's to
//! collect). A plan crosses as an opaque `WasmExtractionPlan`, so the
//! extraction runs core's own plan, never an edited copy; `view()` shows it.
//! An unknown platform, word, destination, position, selection or reason
//! throws, never passes.

use std::collections::BTreeMap;

use beebeeb_core::archives::limits::MAX_SUPPLIED_BYTES;
use beebeeb_core::archives::preview::{progress_text, refusal_text, skip_text, summary_text};
use beebeeb_core::archives::words::{count_label, size_label};
use beebeeb_core::archives::{
    ArchiveEntry, ArchiveIdentity, ArchiveKey, ArchiveListing, ArchivePassword, ArchivePlatform, ArchivePreviewModel,
    ArchiveRefusal, ArchiveSession, ArchiveText, ArchiveTime, ByteRange, ByteSource, DestinationInfo, DestinationKind,
    EntryCipher, EntryStream, ExtractOutcome, ExtractProgress, ExtractRequest, ExtractStep, ExtractSummary, Extraction,
    ExtractionPlan, FailReason, ListingState, PasswordStep, PieceStep, PlanTarget, PreviewInput, Selection,
    SessionStep, SkipReason, SuppliedBytes, archive_preview, archive_text, plan_extraction,
};
use beebeeb_core::backup::BackupPosition;
use beebeeb_core::name_clash::TakenNames;
use serde::{Deserialize, Serialize, Serializer};
use wasm_bindgen::prelude::*;

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_large_number_types_as_bigints(true)
        .serialize_missing_as_null(true)
        .serialize_maps_as_objects(true);
    value.serialize(&serializer).map_err(|e| JsError::new(&e.to_string()))
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue, what: &str) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&format!("invalid {what}: {e}")))
}

fn parse_platform(platform: &str) -> Result<ArchivePlatform, JsError> {
    ArchivePlatform::parse(platform).ok_or_else(|| JsError::new("unknown archive platform"))
}

/// Bytes that cross as a `Uint8Array`.
struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

// ── Shapes ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TextJs {
    key: &'static str,
    text: String,
    args: BTreeMap<String, String>,
}

impl From<&ArchiveText> for TextJs {
    fn from(t: &ArchiveText) -> Self {
        Self {
            key: t.key,
            text: t.text.clone(),
            args: t.args.iter().cloned().collect(),
        }
    }
}

#[derive(Serialize)]
struct SkipJs {
    reason: &'static str,
    detail: Option<String>,
    note: TextJs,
}

fn skip_js(reason: &SkipReason) -> SkipJs {
    SkipJs {
        reason: reason.as_str(),
        detail: reason.detail().map(str::to_string),
        note: (&skip_text(reason)).into(),
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CipherJs {
    None,
    Zipcrypto,
    Aes { bits: u16, ae: u8 },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TimeJs {
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

fn time_js(time: &ArchiveTime) -> TimeJs {
    match *time {
        ArchiveTime::Utc { unix_ms } => TimeJs::Utc { unix_ms },
        ArchiveTime::Local {
            year,
            month,
            day,
            hour,
            minute,
            second,
        } => TimeJs::Local {
            year,
            month,
            day,
            hour,
            minute,
            second,
        },
    }
}

#[derive(Serialize)]
struct EntryJs {
    index: u32,
    display_path: String,
    path: Option<String>,
    kind: &'static str,
    size: u64,
    compressed_size: u64,
    cipher: CipherJs,
    modified: Option<TimeJs>,
    skip: Option<SkipJs>,
}

fn entry_js(e: &ArchiveEntry) -> EntryJs {
    EntryJs {
        index: e.index,
        display_path: e.display_path.clone(),
        path: e.path.as_ref().map(|p| p.joined()),
        kind: e.kind.as_str(),
        size: e.size,
        compressed_size: e.compressed_size,
        cipher: match e.cipher {
            EntryCipher::None => CipherJs::None,
            EntryCipher::ZipCrypto => CipherJs::Zipcrypto,
            EntryCipher::Aes { bits, ae } => CipherJs::Aes { bits, ae },
        },
        modified: e.modified.as_ref().map(time_js),
        skip: e.skip.as_ref().map(skip_js),
    }
}

#[derive(Serialize)]
struct TotalsJs {
    files: u32,
    folders: u32,
    bytes: u64,
    compressed_bytes: u64,
    skipped: u32,
}

#[derive(Serialize)]
struct ListingJs {
    format: &'static str,
    entries: Vec<EntryJs>,
    totals: TotalsJs,
    protection: &'static str,
    uses_zipcrypto: bool,
    complete: bool,
}

fn listing_js(l: &ArchiveListing) -> ListingJs {
    ListingJs {
        format: l.format.as_str(),
        entries: l.entries.iter().map(entry_js).collect(),
        totals: TotalsJs {
            files: l.totals.files,
            folders: l.totals.folders,
            bytes: l.totals.bytes,
            compressed_bytes: l.totals.compressed_bytes,
            skipped: l.totals.skipped,
        },
        protection: l.protection.as_str(),
        uses_zipcrypto: l.uses_zipcrypto,
        complete: l.complete,
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SessionStepJs {
    NeedBytes {
        start: u64,
        end: u64,
    },
    Listed,
    Refused {
        refusal: &'static str,
        format: Option<&'static str>,
        text: TextJs,
    },
    Io {
        message: String,
    },
}

fn refused_js(refusal: ArchiveRefusal) -> SessionStepJs {
    SessionStepJs::Refused {
        refusal: refusal.as_str(),
        format: match refusal {
            ArchiveRefusal::Foreign(format) => Some(format.as_str()),
            _ => None,
        },
        text: (&refusal_text(refusal)).into(),
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PasswordStepJs {
    NeedBytes { start: u64, end: u64 },
    Accepted,
    Wrong,
    NotNeeded,
    Io { message: String },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OpenJs<'a> {
    NeedBytes { start: u64, end: u64 },
    Bytes { bytes: Bytes<'a> },
    Corrupt,
    Wrong,
    Skipped { reason: SkipJs },
    TooLarge,
    Io { message: String },
}

#[derive(Deserialize)]
struct PreviewInputJs {
    archive_name: String,
    #[serde(default)]
    folder: Vec<String>,
    #[serde(default)]
    selection: Vec<String>,
    destination: String,
    /// `true` or `false` (the last password was wrong) while a password is
    /// asked for.
    #[serde(default)]
    password: Option<bool>,
}

#[derive(Serialize)]
struct StateJs {
    kind: &'static str,
    wrong: Option<bool>,
}

#[derive(Serialize)]
struct ActionJs {
    kind: &'static str,
    label: TextJs,
    enabled: bool,
}

#[derive(Serialize)]
struct RowJs {
    name: String,
    kind: &'static str,
    entry: Option<u32>,
    size_label: Option<String>,
    modified: Option<TimeJs>,
    locked: bool,
    note: Option<TextJs>,
    actions: Vec<&'static str>,
}

#[derive(Serialize)]
struct ModelJs {
    state: StateJs,
    title: String,
    kind_label: Option<TextJs>,
    summary: Option<TextJs>,
    notices: Vec<TextJs>,
    path: Vec<String>,
    rows: Vec<RowJs>,
    actions: Vec<ActionJs>,
    selection_actions: Vec<ActionJs>,
}

fn model_js(m: &ArchivePreviewModel) -> ModelJs {
    let actions = |list: &[beebeeb_core::archives::PreviewAction]| {
        list.iter()
            .map(|a| ActionJs {
                kind: a.kind.as_str(),
                label: (&a.label).into(),
                enabled: a.enabled,
            })
            .collect()
    };
    ModelJs {
        state: StateJs {
            kind: m.state.as_str(),
            wrong: match m.state {
                beebeeb_core::archives::PreviewState::NeedsPassword { wrong } => Some(wrong),
                _ => None,
            },
        },
        title: m.title.clone(),
        kind_label: m.kind_label.as_ref().map(Into::into),
        summary: m.summary.as_ref().map(Into::into),
        notices: m.notices.iter().map(Into::into).collect(),
        path: m.path.clone(),
        rows: m
            .rows
            .iter()
            .map(|r| RowJs {
                name: r.name.clone(),
                kind: r.kind.as_str(),
                entry: r.entry,
                size_label: r.size_label.clone(),
                modified: r.modified.as_ref().map(time_js),
                locked: r.locked,
                note: r.note.as_ref().map(Into::into),
                actions: r.actions.iter().map(|a| a.as_str()).collect(),
            })
            .collect(),
        actions: actions(&m.actions),
        selection_actions: actions(&m.selection_actions),
    }
}

/// `preview()` for either side: the listing state, the person's input and
/// whatever the extraction reported.
fn preview_js(
    input: JsValue,
    listing: ListingState<'_>,
    platform: ArchivePlatform,
    progress: Option<&ExtractProgress>,
    summary: Option<&ExtractSummary>,
    plan: Option<&ExtractionPlan>,
) -> Result<JsValue, JsError> {
    let input: PreviewInputJs = from_js(input, "preview input")?;
    let destination = DestinationKind::parse(&input.destination).ok_or_else(|| JsError::new("unknown destination"))?;
    let model = archive_preview(&PreviewInput {
        archive_name: &input.archive_name,
        listing,
        folder: &input.folder,
        selection: &input.selection,
        platform,
        destination,
        password: input.password,
        progress,
        summary,
        plan,
    });
    to_js(&model_js(&model))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SelectionJs {
    /// `"all"`.
    All(String),
    Paths(Vec<String>),
}

#[derive(Deserialize)]
struct DestinationJs {
    siblings: Vec<String>,
    backup_position: Option<String>,
    writable: bool,
}

#[derive(Deserialize)]
struct PlanRequestJs {
    archive_name: String,
    selection: SelectionJs,
    destination: DestinationJs,
    server_free_bytes: u64,
    #[serde(default)]
    device_free_bytes: Option<u64>,
}

#[derive(Serialize)]
struct PlanRefusedJs {
    kind: &'static str,
    refusal: &'static str,
    text: TextJs,
}

#[derive(Serialize)]
struct TargetJs {
    kind: &'static str,
    node: u32,
}

#[derive(Serialize)]
struct NodeJs {
    id: u32,
    parent: Option<u32>,
    name: String,
    kind: &'static str,
    entry: Option<u32>,
    size: u64,
}

#[derive(Serialize)]
struct PlanSkipJs {
    entry: u32,
    reason: SkipJs,
}

#[derive(Serialize)]
struct PlanRenamedJs {
    entry: u32,
    name: String,
}

#[derive(Serialize)]
struct PlanJs {
    target: TargetJs,
    nodes: Vec<NodeJs>,
    skipped: Vec<PlanSkipJs>,
    renamed: Vec<PlanRenamedJs>,
    totals: TotalsJs,
    notices: Vec<TextJs>,
}

#[derive(Deserialize)]
struct IdentityJs {
    file_id: String,
    object_version_id: String,
}

fn identity(value: JsValue) -> Result<ArchiveIdentity, JsError> {
    let id: IdentityJs = from_js(value, "archive identity")?;
    Ok(ArchiveIdentity {
        file_id: id.file_id,
        object_version_id: id.object_version_id,
    })
}

#[derive(Serialize)]
struct SummarySkipJs {
    path: String,
    reason: SkipJs,
}

#[derive(Serialize)]
struct SummaryRenamedJs {
    path: String,
    name: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExtractStepJs<'a> {
    NeedBytes {
        start: u64,
        end: u64,
    },
    NeedPassword {
        entry: u32,
        wrong: bool,
    },
    CreateFolder {
        node: u32,
        parent: Option<u32>,
        name: &'a str,
    },
    FileBegin {
        node: u32,
        parent: Option<u32>,
        name: &'a str,
        size: u64,
    },
    FileData {
        node: u32,
        bytes: Bytes<'a>,
    },
    FileEnd {
        node: u32,
    },
    FileSkipped {
        node: u32,
        reason: SkipJs,
    },
    Progress {
        files_done: u32,
        files_total: u32,
        bytes_done: u64,
        bytes_total: u64,
        current: &'a str,
        text: TextJs,
    },
    Waiting,
    Finished {
        outcome: &'static str,
        reason: Option<&'static str>,
        target_name: &'a str,
        files_done: u32,
        files_total: u32,
        skipped: Vec<SummarySkipJs>,
        renamed: Vec<SummaryRenamedJs>,
        text: TextJs,
    },
}

fn extract_step_js(step: &ExtractStep) -> ExtractStepJs<'_> {
    match step {
        ExtractStep::NeedBytes(ByteRange { start, end }) => ExtractStepJs::NeedBytes {
            start: *start,
            end: *end,
        },
        ExtractStep::NeedPassword { entry, wrong } => ExtractStepJs::NeedPassword {
            entry: *entry,
            wrong: *wrong,
        },
        ExtractStep::CreateFolder { node, parent, name } => ExtractStepJs::CreateFolder {
            node: *node,
            parent: *parent,
            name,
        },
        ExtractStep::FileBegin {
            node,
            parent,
            name,
            size,
        } => ExtractStepJs::FileBegin {
            node: *node,
            parent: *parent,
            name,
            size: *size,
        },
        ExtractStep::FileData { node, bytes } => ExtractStepJs::FileData {
            node: *node,
            bytes: Bytes(bytes),
        },
        ExtractStep::FileEnd { node } => ExtractStepJs::FileEnd { node: *node },
        ExtractStep::FileSkipped { node, reason } => ExtractStepJs::FileSkipped {
            node: *node,
            reason: skip_js(reason),
        },
        ExtractStep::Progress(p) => ExtractStepJs::Progress {
            files_done: p.files_done,
            files_total: p.files_total,
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            current: &p.current,
            text: (&progress_text(p)).into(),
        },
        ExtractStep::Waiting => ExtractStepJs::Waiting,
        ExtractStep::Finished(s) => ExtractStepJs::Finished {
            outcome: s.outcome.as_str(),
            reason: match s.outcome {
                ExtractOutcome::Failed(reason) => Some(reason.as_str()),
                _ => None,
            },
            target_name: &s.target_name,
            files_done: s.files_done,
            files_total: s.files_total,
            skipped: s
                .skipped
                .iter()
                .map(|(path, reason)| SummarySkipJs {
                    path: path.clone(),
                    reason: skip_js(reason),
                })
                .collect(),
            renamed: s
                .renamed
                .iter()
                .map(|(path, name)| SummaryRenamedJs {
                    path: path.clone(),
                    name: name.clone(),
                })
                .collect(),
            text: (&summary_text(s)).into(),
        },
    }
}

// ── Words ──────────────────────────────────────────────────────────────────

/// Core's words for `key` with `args` (`{name: value}`, values already
/// formatted): `{key, text, args}`. An unknown key throws.
#[wasm_bindgen(js_name = archiveText)]
pub fn archive_text_js(key: &str, args: JsValue) -> Result<JsValue, JsError> {
    let key = ArchiveKey::parse(key).ok_or_else(|| JsError::new("unknown archive word"))?;
    let args: BTreeMap<String, String> = from_js(args, "word arguments")?;
    let pairs: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    to_js(&TextJs::from(&archive_text(key, &pairs)))
}

/// A count as the archive words show it (`1,234`).
#[wasm_bindgen(js_name = archiveCountLabel)]
pub fn archive_count_label(n: u64) -> String {
    count_label(n)
}

/// A size as the archive words show it (`3.4 MB`).
#[wasm_bindgen(js_name = archiveSizeLabel)]
pub fn archive_size_label(bytes: u64) -> String {
    size_label(bytes)
}

// ── The session ────────────────────────────────────────────────────────────

struct Reading {
    index: u32,
    stream: EntryStream,
    out: Vec<u8>,
}

/// One archive being listed, previewed and opened. The driver answers each
/// `need_bytes` with `supply` and asks again.
#[wasm_bindgen]
pub struct WasmArchiveSession {
    session: Option<ArchiveSession<SuppliedBytes>>,
    /// What `step` last refused, for the preview.
    refused: Option<ArchiveRefusal>,
    reading: Option<Reading>,
}

/// A plan from `WasmArchiveSession.plan`, for `startExtraction` and the
/// preview.
#[wasm_bindgen]
pub struct WasmExtractionPlan {
    plan: ExtractionPlan,
}

#[wasm_bindgen]
impl WasmExtractionPlan {
    /// `"planned"`, to tell it from a refusal.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        "planned".to_string()
    }

    /// The plan as data: `{target, nodes, skipped, renamed, totals, notices}`.
    pub fn view(&self) -> Result<JsValue, JsError> {
        let p = &self.plan;
        let (kind, node) = match p.target {
            PlanTarget::Folder(node) => ("folder", node),
            PlanTarget::File(node) => ("file", node),
        };
        to_js(&PlanJs {
            target: TargetJs { kind, node },
            nodes: p
                .nodes
                .iter()
                .map(|n| NodeJs {
                    id: n.id,
                    parent: n.parent,
                    name: n.name.clone(),
                    kind: n.kind.as_str(),
                    entry: n.entry,
                    size: n.size,
                })
                .collect(),
            skipped: p
                .skipped
                .iter()
                .map(|(entry, reason)| PlanSkipJs {
                    entry: *entry,
                    reason: skip_js(reason),
                })
                .collect(),
            renamed: p
                .renamed
                .iter()
                .map(|(entry, name)| PlanRenamedJs {
                    entry: *entry,
                    name: name.clone(),
                })
                .collect(),
            totals: TotalsJs {
                files: p.totals.files,
                folders: p.totals.folders,
                bytes: p.totals.bytes,
                compressed_bytes: p.totals.compressed_bytes,
                skipped: p.totals.skipped,
            },
            notices: p.notices.iter().map(Into::into).collect(),
        })
    }
}

impl WasmArchiveSession {
    fn inner(&mut self) -> Result<&mut ArchiveSession<SuppliedBytes>, JsError> {
        self.session
            .as_mut()
            .ok_or_else(|| JsError::new("the session moved into an extraction"))
    }

    fn preview_for(&mut self, input: JsValue, plan: Option<&ExtractionPlan>) -> Result<JsValue, JsError> {
        let refused = self.refused;
        let session = self.inner()?;
        let platform = session.platform();
        let listing = match (session.listing(), refused) {
            (Some(listing), _) => ListingState::Listed(listing),
            (None, Some(refusal)) => ListingState::Refused(refusal),
            (None, None) => ListingState::Reading,
        };
        preview_js(input, listing, platform, None, None, plan)
    }
}

#[wasm_bindgen]
impl WasmArchiveSession {
    /// A session for an archive of `len` bytes on `platform` (`"native"`,
    /// `"browser"` or `"mobile_app"`).
    #[wasm_bindgen(constructor)]
    pub fn new(len: u64, platform: &str) -> Result<WasmArchiveSession, JsError> {
        let platform = parse_platform(platform)?;
        Ok(Self {
            session: Some(ArchiveSession::open(
                SuppliedBytes::new(len, MAX_SUPPLIED_BYTES),
                platform,
            )),
            refused: None,
            reading: None,
        })
    }

    /// `{kind: "need_bytes", start, end}`, `{kind: "listed"}`,
    /// `{kind: "refused", refusal, format, text}` or `{kind: "io", message}`.
    pub fn step(&mut self) -> Result<JsValue, JsError> {
        let step = match self.inner()?.step() {
            SessionStep::NeedBytes(r) => SessionStepJs::NeedBytes {
                start: r.start,
                end: r.end,
            },
            SessionStep::Listed => SessionStepJs::Listed,
            SessionStep::Refused(refusal) => {
                self.refused = Some(refusal);
                refused_js(refusal)
            }
            SessionStep::Io(message) => SessionStepJs::Io { message },
        };
        to_js(&step)
    }

    /// The bytes at `offset`. Throws when they fall outside the archive or
    /// differ from bytes already supplied there.
    pub fn supply(&mut self, offset: u64, bytes: Vec<u8>) -> Result<(), JsError> {
        self.inner()?
            .source_mut()
            .supply(offset, bytes)
            .map_err(|_| JsError::new("the supplied bytes do not fit the archive"))
    }

    /// Bytes before `offset` are no longer needed.
    #[wasm_bindgen(js_name = releaseBefore)]
    pub fn release_before(&mut self, offset: u64) -> Result<(), JsError> {
        self.inner()?.source_mut().release_before(offset);
        Ok(())
    }

    /// The listing (`{format, entries, totals, protection, uses_zipcrypto,
    /// complete}`), or `null` before `listed`.
    pub fn listing(&mut self) -> Result<JsValue, JsError> {
        match self.inner()?.listing() {
            Some(listing) => to_js(&listing_js(listing)),
            None => Ok(JsValue::NULL),
        }
    }

    /// Whether `password` opens entry `index`: `{kind: "need_bytes", start,
    /// end}`, `"accepted"`, `"wrong"`, `"not_needed"` or `{kind: "io",
    /// message}`.
    #[wasm_bindgen(js_name = checkPassword)]
    pub fn check_password(&mut self, index: u32, password: String) -> Result<JsValue, JsError> {
        let password = ArchivePassword::new(password);
        let step = match self.inner()?.check_password(index, &password) {
            PasswordStep::NeedBytes(r) => PasswordStepJs::NeedBytes {
                start: r.start,
                end: r.end,
            },
            PasswordStep::Accepted => PasswordStepJs::Accepted,
            PasswordStep::Wrong => PasswordStepJs::Wrong,
            PasswordStep::NotNeeded => PasswordStepJs::NotNeeded,
            PasswordStep::Io(message) => PasswordStepJs::Io { message },
        };
        to_js(&step)
    }

    /// The preview model. `input`: `{archive_name, folder, selection,
    /// destination: "next_to" | "choose_folder", password: null | boolean}`.
    pub fn preview(&mut self, input: JsValue) -> Result<JsValue, JsError> {
        self.preview_for(input, None)
    }

    /// The preview model with a plan's notes (renamed entries, the browser's
    /// size limit).
    #[wasm_bindgen(js_name = previewWithPlan)]
    pub fn preview_with_plan(&mut self, input: JsValue, plan: &WasmExtractionPlan) -> Result<JsValue, JsError> {
        self.preview_for(input, Some(&plan.plan))
    }

    /// Plan an extraction of the listed archive: a `WasmExtractionPlan`, or
    /// `{kind: "refused", refusal, text}`. `request`: `{archive_name,
    /// selection: "all" | [path], destination: {siblings, backup_position,
    /// writable}, server_free_bytes, device_free_bytes}`.
    pub fn plan(&mut self, request: JsValue) -> Result<JsValue, JsError> {
        let session = self.inner()?;
        let platform = session.platform();
        let listing = session
            .listing()
            .ok_or_else(|| JsError::new("the archive is not listed"))?;
        let r: PlanRequestJs = from_js(request, "plan request")?;
        let selection = match r.selection {
            SelectionJs::All(all) if all == "all" => Selection::All,
            SelectionJs::All(_) => return Err(JsError::new("unknown selection")),
            SelectionJs::Paths(paths) => Selection::Paths(paths),
        };
        let backup_position = match r.destination.backup_position.as_deref() {
            None => None,
            Some(p) => Some(BackupPosition::parse(p).ok_or_else(|| JsError::new("unknown backup position"))?),
        };
        let mut siblings = TakenNames::new();
        for name in &r.destination.siblings {
            siblings.insert(name);
        }
        let request = ExtractRequest {
            archive_name: r.archive_name,
            selection,
            destination: DestinationInfo {
                siblings,
                backup_position,
                writable: r.destination.writable,
            },
            server_free_bytes: r.server_free_bytes,
            device_free_bytes: r.device_free_bytes,
            platform,
        };
        match plan_extraction(listing, &request) {
            Ok(plan) => Ok(WasmExtractionPlan { plan }.into()),
            Err(refusal) => to_js(&PlanRefusedJs {
                kind: "refused",
                refusal: refusal.as_str(),
                text: (&refusal.text()).into(),
            }),
        }
    }

    /// Start extracting `plan`, bound to `identity` (`{file_id,
    /// object_version_id}`); a password from the preview is passed on. The
    /// session moves into the extraction: every later call on it throws.
    #[wasm_bindgen(js_name = startExtraction)]
    pub fn start_extraction(
        &mut self,
        identity_js: JsValue,
        plan: &WasmExtractionPlan,
        password: Option<String>,
    ) -> Result<WasmArchiveExtraction, JsError> {
        let identity = identity(identity_js)?;
        if self.inner()?.listing().is_none() {
            return Err(JsError::new("the archive is not listed"));
        }
        let session = self.session.take().expect("checked above");
        self.reading = None;
        let platform = session.platform();
        let extraction = Extraction::start(session, identity, plan.plan.clone(), password.map(ArchivePassword::new));
        Ok(WasmArchiveExtraction {
            extraction,
            platform,
            progress: None,
            summary: None,
        })
    }

    /// Read entry `index` whole, to open it: `{kind: "need_bytes", start,
    /// end}` (supply, then call again with the same index), `{kind:
    /// "bytes", bytes}` once its check passed, `"corrupt"`, `"wrong"`,
    /// `{kind: "skipped", reason}`, `"too_large"` (over the platform's
    /// open budget) or `{kind: "io", message}`. `password` is used when a
    /// read starts.
    #[wasm_bindgen(js_name = openEntry)]
    pub fn open_entry(&mut self, index: u32, password: Option<String>) -> Result<JsValue, JsError> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| JsError::new("the session moved into an extraction"))?;
        let budget = session.platform().budget().archive_output_bytes;
        let size = session
            .listing()
            .ok_or_else(|| JsError::new("the archive is not listed"))?
            .entries
            .get(index as usize)
            .ok_or_else(|| JsError::new("no such entry"))?
            .size;
        if size > budget {
            self.reading = None;
            return to_js(&OpenJs::TooLarge);
        }
        if self.reading.as_ref().map(|r| r.index) != Some(index) {
            let password = password.map(ArchivePassword::new);
            let stream = session
                .entry_stream(index, password.as_ref())
                .map_err(|_| JsError::new("no such entry"))?;
            self.reading = Some(Reading {
                index,
                stream,
                out: Vec::new(),
            });
        }
        let reading = self.reading.as_mut().expect("set above");
        loop {
            let done = match reading.stream.next_piece(session) {
                PieceStep::Data(piece) => {
                    reading.out.extend_from_slice(&piece);
                    if reading.out.len() as u64 > budget {
                        OpenJs::TooLarge
                    } else {
                        continue;
                    }
                }
                PieceStep::NeedBytes(r) => {
                    return to_js(&OpenJs::NeedBytes {
                        start: r.start,
                        end: r.end,
                    });
                }
                PieceStep::Verified => {
                    let out = std::mem::take(&mut reading.out);
                    self.reading = None;
                    return to_js(&OpenJs::Bytes { bytes: Bytes(&out) });
                }
                PieceStep::Corrupt => OpenJs::Corrupt,
                PieceStep::WrongPassword => OpenJs::Wrong,
                PieceStep::Skipped(reason) => OpenJs::Skipped {
                    reason: skip_js(&reason),
                },
                PieceStep::Io(message) => OpenJs::Io { message },
            };
            self.reading = None;
            return to_js(&done);
        }
    }
}

// ── The extraction ─────────────────────────────────────────────────────────

/// One extraction run. The driver acts on each step (create the folder,
/// stage and upload the file, supply bytes, ask for the password) and
/// reports back.
#[wasm_bindgen]
pub struct WasmArchiveExtraction {
    extraction: Extraction<SuppliedBytes>,
    platform: ArchivePlatform,
    progress: Option<ExtractProgress>,
    summary: Option<ExtractSummary>,
}

#[wasm_bindgen]
impl WasmArchiveExtraction {
    /// The next step: `{kind}` is `need_bytes`, `need_password`,
    /// `create_folder`, `file_begin`, `file_data` (`bytes` a `Uint8Array`,
    /// not yet verified), `file_end`, `file_skipped`, `progress`, `waiting`
    /// or `finished`.
    pub fn step(&mut self) -> Result<JsValue, JsError> {
        let step = self.extraction.step();
        match &step {
            ExtractStep::Progress(p) => self.progress = Some(p.clone()),
            ExtractStep::Finished(s) => self.summary = Some(s.clone()),
            _ => {}
        }
        to_js(&extract_step_js(&step))
    }

    /// The bytes at `offset`, as for the session.
    pub fn supply(&mut self, offset: u64, bytes: Vec<u8>) -> Result<(), JsError> {
        self.extraction
            .source_mut()
            .supply(offset, bytes)
            .map_err(|_| JsError::new("the supplied bytes do not fit the archive"))
    }

    #[wasm_bindgen(js_name = releaseBefore)]
    pub fn release_before(&mut self, offset: u64) {
        self.extraction.source_mut().release_before(offset);
    }

    /// The folder for `create_folder`'s `node` exists, with this id.
    #[wasm_bindgen(js_name = folderCreated)]
    pub fn folder_created(&mut self, node: u32, id: String) {
        self.extraction.folder_created(node, id);
    }

    /// The server answered 409 for `node`'s name: core numbers it again.
    #[wasm_bindgen(js_name = folderNameTaken)]
    pub fn folder_name_taken(&mut self, node: u32) {
        self.extraction.folder_name_taken(node);
    }

    /// `node`'s upload finished (`ok`) or failed.
    #[wasm_bindgen(js_name = uploadFinished)]
    pub fn upload_finished(&mut self, node: u32, ok: bool) {
        self.extraction.upload_finished(node, ok);
    }

    /// The archive as the server lists it now (`{file_id,
    /// object_version_id}`): another version stops the run.
    #[wasm_bindgen(js_name = identitySeen)]
    pub fn identity_seen(&mut self, identity_js: JsValue) -> Result<(), JsError> {
        self.extraction.identity_seen(&identity(identity_js)?);
        Ok(())
    }

    /// The run cannot go on: `"storage_full"`, `"network"`, `"damaged"`,
    /// `"changed"` or `"account_blocked"`.
    #[wasm_bindgen(js_name = runFailed)]
    pub fn run_failed(&mut self, reason: &str) -> Result<(), JsError> {
        let reason = FailReason::parse(reason).ok_or_else(|| JsError::new("unknown fail reason"))?;
        self.extraction.run_failed(reason);
        Ok(())
    }

    /// The password the person entered for `need_password`.
    #[wasm_bindgen(js_name = supplyPassword)]
    pub fn supply_password(&mut self, password: String) {
        self.extraction.supply_password(ArchivePassword::new(password));
    }

    pub fn cancel(&mut self) {
        self.extraction.cancel();
    }

    /// The preview model while the run goes and after it ends; `input` as
    /// for the session.
    pub fn preview(&self, input: JsValue) -> Result<JsValue, JsError> {
        let listing = self
            .extraction
            .listing()
            .ok_or_else(|| JsError::new("the archive is not listed"))?;
        preview_js(
            input,
            ListingState::Listed(listing),
            self.platform,
            self.progress.as_ref(),
            self.summary.as_ref(),
            Some(self.extraction.plan()),
        )
    }
}
