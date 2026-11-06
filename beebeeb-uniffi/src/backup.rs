//! The backup rules for iOS (and later Android): LD-0113, spec
//! `2026-11-06-backup-from-source-design.md` §4.4. Every function forwards to
//! `beebeeb_core::backup`; no rule lives here. Ids and keys cross as strings.
//! Any string this side must parse (a mutation, a role, a platform, a record
//! state, an id) that it does not know is `CryptoError::InvalidInput`, never a
//! pass (plan Amendment 1, item 3). Split out of `lib.rs`, which is over the
//! file-size ratchet.

use std::collections::{HashMap, HashSet};

use beebeeb_core::backup as rules;
use beebeeb_types::backup::{ORIGIN_BACKUP, ORIGIN_HEADER, Platform, SystemRole};
use uuid::Uuid;

use super::CryptoError;

fn invalid(detail: impl Into<String>) -> CryptoError {
    CryptoError::InvalidInput { detail: detail.into() }
}

fn parse_id(field: &str, s: &str) -> Result<Uuid, CryptoError> {
    Uuid::parse_str(s).map_err(|_| invalid(format!("{field} is not a UUID")))
}

fn parse_ids(field: &str, ids: &[String]) -> Result<Vec<Uuid>, CryptoError> {
    ids.iter().map(|s| parse_id(field, s)).collect()
}

/// `None` or `""` is no role; `"backups_root"` is the root; anything else is
/// an error.
fn parse_role(role: Option<&str>) -> Result<Option<SystemRole>, CryptoError> {
    match role {
        None | Some("") => Ok(None),
        Some(s) => SystemRole::parse(s)
            .map(Some)
            .ok_or_else(|| invalid("unknown system role")),
    }
}

fn parse_platform(s: &str) -> Result<Platform, CryptoError> {
    Platform::parse(s).ok_or_else(|| invalid("unknown platform"))
}

// ── Protection and skip ────────────────────────────────────────────────────

fn parse_mutation(s: &str) -> Result<rules::Mutation, CryptoError> {
    rules::Mutation::parse(s).ok_or_else(|| invalid("unknown mutation"))
}

fn parse_position(s: &str) -> Result<rules::BackupPosition, CryptoError> {
    rules::BackupPosition::parse(s).ok_or_else(|| invalid("unknown backup position"))
}

/// The server's root rule (spec Amendment 8): the words to show when
/// `mutation` (`"trash" | "delete" | "rename" | "move" | "create" | "write"`)
/// of a row with `role` is refused, or `None` when it is allowed. Only the
/// root's trash, delete, rename and move are refused; the app and drive rules
/// below are the whole rule.
#[uniffi::export]
pub fn backup_check_root_mutation(role: Option<String>, mutation: String) -> Result<Option<String>, CryptoError> {
    let m = parse_mutation(&mutation)?;
    Ok(rules::check_root_mutation(parse_role(role.as_deref())?, m)
        .err()
        .map(|p| p.message.to_string()))
}

/// The app rule (the iOS app; spec Amendment 8): the words to show when
/// `mutation` of a row at `position` (`"root" | "device_folder" | "manifest" |
/// "category_folder" | "inside" | "outside"`, from
/// [`backup_position_at_depth`]; for `"create"`, the folder the new item goes
/// into) is refused, or `None`. A move checks the row with `"move"` and the
/// destination folder with `"create"`.
#[uniffi::export]
pub fn backup_check_app_mutation(position: String, mutation: String) -> Result<Option<String>, CryptoError> {
    let m = parse_mutation(&mutation)?;
    Ok(rules::check_app_mutation(parse_position(&position)?, m)
        .err()
        .map(|p| p.message.to_string()))
}

/// The drive rule (the iOS Files app): the words to show when `mutation` of a
/// row at `position` is refused, or `None`. Nothing at or under the root is
/// changed in a drive surface. `own_active_source`: the original's path when
/// the row is this device's own backup of a folder still being backed up.
#[uniffi::export]
pub fn backup_check_drive_mutation(
    position: String,
    own_active_source: Option<String>,
    mutation: String,
) -> Result<Option<String>, CryptoError> {
    let m = parse_mutation(&mutation)?;
    Ok(
        rules::check_drive_mutation(parse_position(&position)?, own_active_source.as_deref(), m)
            .err()
            .map(|p| p.message.into_owned()),
    )
}

/// The position of the row `name`, `depth` folders below the flagged root
/// (`None`: not under it): `"outside"`, `"root"` (0), `"device_folder"` (1),
/// `"manifest"` (2, a device folder's `.device.json`), `"category_folder"`
/// (2) or `"inside"` (3 or more).
#[uniffi::export]
pub fn backup_position_at_depth(depth: Option<u32>, name: String) -> String {
    rules::BackupPosition::at_depth(depth.map(|d| d as usize), &name)
        .as_str()
        .to_string()
}

/// `true` for a row no listing ever shows (a device folder's `.device.json`);
/// `depth` and `name` as for [`backup_position_at_depth`].
#[uniffi::export]
pub fn backup_is_hidden_item(depth: Option<u32>, name: String) -> bool {
    rules::is_hidden_backup_item(depth.map(|d| d as usize), &name)
}

/// The badge every client shows on the Backups root (`"Read-only"`).
#[uniffi::export]
pub fn backup_root_badge() -> String {
    rules::MSG_BADGE.to_string()
}

/// The name a new root gets on [`BackupRootPlan::Create`] (`"Backups"`). It
/// identifies nothing: the root is the `backups_root` row.
#[uniffi::export]
pub fn backup_root_name() -> String {
    rules::ROOT_NAME.to_string()
}

/// One HTTP header, name and value.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupHeader {
    pub name: String,
    pub value: String,
}

/// The header every request of a backup pass carries (spec Amendment 8):
/// `X-Beebeeb-Origin: backup`. iOS's backup sends it on its listing, folder,
/// move and upload requests, and nothing else does; the server ignores it
/// until phase 2.
#[uniffi::export]
pub fn backup_origin_header() -> BackupHeader {
    BackupHeader {
        name: ORIGIN_HEADER.to_string(),
        value: ORIGIN_BACKUP.to_string(),
    }
}

/// Why an entry is never backed up (`"junk"`, `"not_local"`, ...), or `None`.
#[uniffi::export]
pub fn backup_skip_reason(name: String, is_dir: bool, is_link: bool, not_local: bool) -> Option<String> {
    let attrs = rules::EntryAttrs {
        is_dir,
        is_link,
        not_local,
    };
    rules::skip_reason(&name, &attrs).map(|r| r.as_str().to_string())
}

// ── Root and merge ─────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct BackupRootCandidate {
    pub id: String,
    /// `None` while the name cannot be decrypted.
    pub name: Option<String>,
    pub is_trashed: bool,
    pub created_at_ms: i64,
    /// `None`, `""` or `"backups_root"`.
    pub system_role: Option<String>,
}

/// What the client does about the root; on `Create` it names the new root
/// [`backup_root_name`].
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BackupRootPlan {
    Use { id: String },
    Claim { id: String, merge_from: Vec<String> },
    Create,
}

#[uniffi::export]
pub fn backup_resolve_root(candidates: Vec<BackupRootCandidate>) -> Result<BackupRootPlan, CryptoError> {
    let candidates = candidates
        .into_iter()
        .map(|c| {
            Ok(rules::RootCandidate {
                id: parse_id("id", &c.id)?,
                name: c.name,
                is_trashed: c.is_trashed,
                created_at_ms: c.created_at_ms,
                system_role: parse_role(c.system_role.as_deref())?,
            })
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    Ok(match rules::resolve_root(&candidates) {
        rules::RootPlan::Use(id) => BackupRootPlan::Use { id: id.to_string() },
        rules::RootPlan::Claim { id, merge_from } => BackupRootPlan::Claim {
            id: id.to_string(),
            merge_from: merge_from.iter().map(Uuid::to_string).collect(),
        },
        rules::RootPlan::Create => BackupRootPlan::Create,
    })
}

/// One row of a tree, flat as a listing gives it. Each tree has exactly one
/// row without a parent (its root: the survivor or a duplicate Backups root),
/// and every other row sits under it. Children keep their listing order.
#[derive(uniffi::Record)]
pub struct BackupMergeEntry {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub is_folder: bool,
}

#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BackupMergeStep {
    Move {
        id: String,
        new_parent: String,
    },
    MoveRenamed {
        id: String,
        new_parent: String,
        new_name: String,
    },
    Trash {
        id: String,
    },
}

struct Row {
    id: Uuid,
    name: String,
    is_folder: bool,
}

fn build_node(
    i: usize,
    rows: &[Row],
    by_parent: &HashMap<Uuid, Vec<usize>>,
    visited: &mut HashSet<usize>,
) -> Result<rules::MergeNode, CryptoError> {
    if !visited.insert(i) {
        return Err(invalid("a merge tree has a cycle"));
    }
    let mut children = Vec::new();
    for &child in by_parent.get(&rows[i].id).map(Vec::as_slice).unwrap_or(&[]) {
        children.push(build_node(child, rows, by_parent, visited)?);
    }
    Ok(rules::MergeNode {
        id: rows[i].id,
        name: rows[i].name.clone(),
        is_folder: rows[i].is_folder,
        children,
    })
}

fn merge_tree(entries: Vec<BackupMergeEntry>) -> Result<rules::MergeNode, CryptoError> {
    let mut rows = Vec::with_capacity(entries.len());
    let mut by_parent: HashMap<Uuid, Vec<usize>> = HashMap::new();
    let mut ids = HashSet::new();
    let mut root = None;
    for (i, entry) in entries.into_iter().enumerate() {
        let id = parse_id("id", &entry.id)?;
        if !ids.insert(id) {
            return Err(invalid("a merge tree lists one id twice"));
        }
        match entry.parent_id.as_deref() {
            Some(parent) => by_parent.entry(parse_id("parent_id", parent)?).or_default().push(i),
            None if root.is_none() => root = Some(i),
            None => return Err(invalid("a merge tree has more than one row without a parent")),
        }
        rows.push(Row {
            id,
            name: entry.name,
            is_folder: entry.is_folder,
        });
    }
    let root = root.ok_or_else(|| invalid("a merge tree has no row without a parent"))?;
    let mut visited = HashSet::new();
    let node = build_node(root, &rows, &by_parent, &mut visited)?;
    if visited.len() != rows.len() {
        return Err(invalid("a merge row is not under its tree's root"));
    }
    Ok(node)
}

/// Pass `hhmm` with a dot (`"14.05"`): a `:` is refused on Windows.
#[uniffi::export]
pub fn backup_plan_merge(
    survivor: Vec<BackupMergeEntry>,
    duplicates: Vec<Vec<BackupMergeEntry>>,
    clash_label: String,
    hhmm: String,
) -> Result<Vec<BackupMergeStep>, CryptoError> {
    let survivor = merge_tree(survivor)?;
    let duplicates = duplicates.into_iter().map(merge_tree).collect::<Result<Vec<_>, _>>()?;
    Ok(rules::plan_merge(&survivor, &duplicates, &clash_label, &hhmm)
        .map_err(|error| invalid(error.to_string()))?
        .into_iter()
        .map(|step| match step {
            rules::MergeStep::Move { id, new_parent } => BackupMergeStep::Move {
                id: id.to_string(),
                new_parent: new_parent.to_string(),
            },
            rules::MergeStep::MoveRenamed {
                id,
                new_parent,
                new_name,
            } => BackupMergeStep::MoveRenamed {
                id: id.to_string(),
                new_parent: new_parent.to_string(),
                new_name,
            },
            rules::MergeStep::Trash { id } => BackupMergeStep::Trash { id: id.to_string() },
        })
        .collect())
}

// ── Device folders and the manifest ────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct BackupTakenName {
    pub name: String,
    pub device_id: Option<String>,
}

#[uniffi::export]
pub fn backup_device_folder_name(
    raw: String,
    my_id: String,
    taken: Vec<BackupTakenName>,
) -> Result<String, CryptoError> {
    let taken: Vec<rules::TakenName> = taken
        .into_iter()
        .map(|t| rules::TakenName {
            name: t.name,
            device_id: t.device_id,
        })
        .collect();
    if my_id.is_empty() {
        return Err(invalid("my_id is empty"));
    }
    Ok(rules::device_folder_name(&raw, &my_id, &taken))
}

#[derive(uniffi::Record)]
pub struct BackupDeviceSelf {
    /// A string identity: a UUID, or the iOS legacy `beebeeb_device_id`
    /// value carried forward verbatim.
    pub device_id: String,
    pub name: String,
    /// `"windows" | "macos" | "linux" | "ios" | "android" | "cli"`.
    pub platform: String,
}

#[derive(uniffi::Record)]
pub struct BackupDeviceFolderCandidate {
    pub folder_id: String,
    pub name: String,
    /// The decrypted `.device.json`, `None` when the folder has none. One that
    /// does not parse counts as an unreadable manifest: not mine, never
    /// adopted, its name taken. It never fails the call.
    pub manifest_json: Option<String>,
}

#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BackupDeviceFolderChoice {
    Existing { folder_id: String },
    AdoptLegacy { folder_id: String },
    Create { name: String },
}

#[uniffi::export]
pub fn backup_find_device_folder(
    me: BackupDeviceSelf,
    candidates: Vec<BackupDeviceFolderCandidate>,
) -> Result<BackupDeviceFolderChoice, CryptoError> {
    if me.device_id.is_empty() {
        return Err(invalid("device_id is empty"));
    }
    let me = rules::DeviceSelf {
        device_id: me.device_id,
        name: me.name,
        platform: parse_platform(&me.platform)?,
    };
    let candidates = candidates
        .into_iter()
        .map(|c| {
            Ok(rules::DeviceFolderCandidate {
                folder_id: parse_id("folder_id", &c.folder_id)?,
                name: c.name,
                manifest: match c.manifest_json.as_deref().map(rules::parse_manifest) {
                    None => rules::FolderManifest::Absent,
                    Some(Ok(m)) => rules::FolderManifest::Parsed(m),
                    Some(Err(_)) => rules::FolderManifest::Unreadable,
                },
            })
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    Ok(match rules::find_device_folder(&me, &candidates) {
        rules::DeviceFolderChoice::Existing(id) => BackupDeviceFolderChoice::Existing {
            folder_id: id.to_string(),
        },
        rules::DeviceFolderChoice::AdoptLegacy(id) => BackupDeviceFolderChoice::AdoptLegacy {
            folder_id: id.to_string(),
        },
        rules::DeviceFolderChoice::Create { name } => BackupDeviceFolderChoice::Create { name },
    })
}

/// One `folders` entry, plus its fields this version does not know as one
/// JSON object string (`other_json`), written back unchanged.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupFolderState {
    pub category: String,
    pub enabled: bool,
    pub last_pass_at_ms: Option<i64>,
    pub items: u64,
    pub other_json: String,
}

fn json_object(text: &str, field: &str) -> Result<serde_json::Map<String, serde_json::Value>, CryptoError> {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(object)) => Ok(object),
        _ => Err(invalid(format!("{field} must be a JSON object"))),
    }
}

/// The manifest's known fields, plus every field this version does not know
/// as one JSON object string (`other_json`), written back unchanged.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupDeviceManifest {
    pub version: u32,
    pub device_id: Option<String>,
    pub device_name: String,
    pub platform: Option<String>,
    pub folders: Vec<BackupFolderState>,
    pub other_json: String,
}

#[uniffi::export]
pub fn backup_parse_manifest(json: String) -> Result<BackupDeviceManifest, CryptoError> {
    let m = rules::parse_manifest(&json)?;
    Ok(BackupDeviceManifest {
        version: m.version,
        device_id: m.device_id,
        device_name: m.device_name,
        platform: m.platform.map(|p| p.as_str().to_string()),
        folders: m
            .folders
            .into_iter()
            .map(|f| BackupFolderState {
                category: f.category,
                enabled: f.enabled,
                last_pass_at_ms: f.last_pass_at_ms,
                items: f.items,
                other_json: serde_json::Value::Object(f.other).to_string(),
            })
            .collect(),
        other_json: serde_json::Value::Object(m.other).to_string(),
    })
}

#[uniffi::export]
pub fn backup_serialize_manifest(manifest: BackupDeviceManifest) -> Result<String, CryptoError> {
    let other = json_object(&manifest.other_json, "other_json")?;
    let m = rules::DeviceManifest {
        version: manifest.version,
        device_id: manifest.device_id,
        device_name: manifest.device_name,
        platform: manifest.platform.as_deref().map(parse_platform).transpose()?,
        folders: manifest
            .folders
            .into_iter()
            .map(|f| {
                Ok(rules::FolderState {
                    category: f.category,
                    enabled: f.enabled,
                    last_pass_at_ms: f.last_pass_at_ms,
                    items: f.items,
                    other: json_object(&f.other_json, "a folder's other_json")?,
                })
            })
            .collect::<Result<_, CryptoError>>()?,
        other,
    };
    Ok(rules::serialize_manifest(&m))
}

// ── The pass planner ───────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct BackupSourceEntry {
    /// A `/`-joined path; every `/` is a folder boundary. iOS passes the
    /// asset id with each `/` replaced by `|` (`<uuid>|L0|001`).
    pub key: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ms: i64,
}

#[derive(uniffi::Record)]
pub struct BackupRecordEntry {
    pub key: String,
    pub size: u64,
    pub modified_ms: i64,
    pub remote_id: String,
    pub uploaded_at_ms: i64,
    /// `"backed_up" | "removed_elsewhere"`.
    pub state: String,
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupPlannedUpload {
    pub key: String,
    pub size: u64,
    /// `"new" | "changed"`.
    pub reason: String,
    /// The paired record's key (re-key it to `key` when the upload completes).
    pub record_key: Option<String>,
    /// For `"changed"`: the remote file to add a version to.
    pub remote_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupPlannedMove {
    pub remote_id: String,
    pub from_key: String,
    pub to_key: String,
}

/// A record as the plan read it. Mark it removed elsewhere only while the
/// record at `key` still names `remote_id` (compare-and-set): a record a
/// finishing upload rewrote since is left alone.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupRecordRef {
    pub key: String,
    pub remote_id: String,
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupPassPlan {
    pub uploads: Vec<BackupPlannedUpload>,
    pub moves: Vec<BackupPlannedMove>,
    pub folders: Vec<String>,
    pub mark_removed_elsewhere: Vec<BackupRecordRef>,
    pub unchanged: u64,
    pub gone_locally: u64,
    pub deferred: u64,
    pub held: u64,
    pub deferred_unknown: u64,
}

fn parse_state(s: &str) -> Result<rules::RecordState, CryptoError> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|_| invalid("unknown record state"))
}

/// `live_remote`: every live file id of the category, a file whose name is
/// still pending decryption included. `live_remote_complete`: the listing read
/// every page and dropped nothing; only then is anything marked removed
/// elsewhere. `unseen`: keys the source did not look at or into (iOS passes
/// an empty list). `held`: keys the client holds (a lasting upload failure, or
/// one in flight), skipped and not charged to the budget. `max_uploads`
/// saturates at the platform's `usize`, and 0 counts as 1: the first upload
/// always fits (review 4 #7). Each `mark_removed_elsewhere` entry carries
/// the remote id the record named, for a compare-and-set mark.
// Flat FFI arguments, as the other uniffi exports with many inputs (lib.rs).
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn backup_plan_pass(
    entries: Vec<BackupSourceEntry>,
    records: Vec<BackupRecordEntry>,
    live_remote: Vec<String>,
    live_remote_complete: bool,
    unseen: Vec<String>,
    held: Vec<String>,
    max_uploads: u64,
    max_bytes: u64,
) -> Result<BackupPassPlan, CryptoError> {
    let entries: Vec<rules::SourceEntry> = entries
        .into_iter()
        .map(|e| rules::SourceEntry {
            key: e.key,
            is_dir: e.is_dir,
            size: e.size,
            modified_ms: e.modified_ms,
        })
        .collect();
    let records = records
        .into_iter()
        .map(|r| {
            Ok(rules::BackupRecord {
                key: r.key,
                size: r.size,
                modified_ms: r.modified_ms,
                remote_id: parse_id("remote_id", &r.remote_id)?,
                uploaded_at_ms: r.uploaded_at_ms,
                state: parse_state(&r.state)?,
            })
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    let live: HashSet<Uuid> = parse_ids("live_remote", &live_remote)?.into_iter().collect();
    let budget = rules::PassBudget {
        max_uploads: usize::try_from(max_uploads).unwrap_or(usize::MAX),
        max_bytes,
    };
    let plan = rules::plan_pass(&entries, &records, &live, live_remote_complete, &unseen, &held, budget);
    Ok(BackupPassPlan {
        uploads: plan
            .uploads
            .into_iter()
            .map(|u| BackupPlannedUpload {
                key: u.key,
                size: u.size,
                reason: match u.reason {
                    rules::UploadReason::New => "new",
                    rules::UploadReason::Changed => "changed",
                }
                .to_string(),
                record_key: u.record_key,
                remote_id: u.remote_id.map(|id| id.to_string()),
            })
            .collect(),
        moves: plan
            .moves
            .into_iter()
            .map(|m| BackupPlannedMove {
                remote_id: m.remote_id.to_string(),
                from_key: m.from_key,
                to_key: m.to_key,
            })
            .collect(),
        folders: plan.folders,
        mark_removed_elsewhere: plan
            .mark_removed_elsewhere
            .into_iter()
            .map(|m| BackupRecordRef {
                key: m.key,
                remote_id: m.remote_id.to_string(),
            })
            .collect(),
        unchanged: plan.unchanged as u64,
        gone_locally: plan.gone_locally as u64,
        deferred: plan.deferred as u64,
        held: plan.held as u64,
        deferred_unknown: plan.deferred_unknown as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_cases(concept: &str) -> Vec<serde_json::Value> {
        let path = format!(
            "{}/../test-vectors/consolidation/{concept}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("json");
        doc["cases"].as_array().expect("cases").clone()
    }

    fn want(case: &serde_json::Value) -> Option<String> {
        match case["expect"].as_str().unwrap() {
            "ok" => None,
            words => Some(words.to_string()),
        }
    }

    /// The server's root rule through the binding, against every root case of
    /// the shared vector (6 mutations x {root, child, other}, plus a move into
    /// the root).
    #[test]
    fn uniffi_backup_check_root_mutation_matches_core() {
        let mut n = 0;
        for case in vector_cases("backup_protect")
            .iter()
            .filter(|c| c["kind"] == "root_mutation")
        {
            let role = case["role"].as_str().map(str::to_string);
            let got = backup_check_root_mutation(role, case["mutation"].as_str().unwrap().to_string())
                .expect("known strings");
            assert_eq!(got, want(case), "{}", case["id"]);
            n += 1;
        }
        assert_eq!(n, 19, "the 6 x 3 matrix plus a move into the root");
    }

    /// The app and drive rules through the binding, against every case of the
    /// shared vector: 6 positions x 6 mutations each, and the drive rule's
    /// own-active cases.
    #[test]
    fn uniffi_backup_check_app_and_drive_mutation_match_core() {
        let (mut app, mut drive) = (0, 0);
        for case in vector_cases("backup_protect") {
            let position = || case["position"].as_str().unwrap().to_string();
            let mutation = || case["mutation"].as_str().unwrap().to_string();
            let got = match case["kind"].as_str().unwrap() {
                "app_mutation" => {
                    app += 1;
                    backup_check_app_mutation(position(), mutation())
                }
                "drive_mutation" => {
                    drive += 1;
                    backup_check_drive_mutation(
                        position(),
                        case["own_active_source"].as_str().map(str::to_string),
                        mutation(),
                    )
                }
                _ => continue,
            };
            assert_eq!(got.expect("known strings"), want(&case), "{}", case["id"]);
        }
        assert_eq!(app, 36, "6 positions x 6 mutations");
        assert_eq!(drive, 43, "6 positions x 6 mutations, 6 own active, 1 precedence");
        for bad in ["erase", "Write", ""] {
            assert!(backup_check_drive_mutation("inside".to_string(), None, bad.to_string()).is_err());
            assert!(backup_check_app_mutation("inside".to_string(), bad.to_string()).is_err());
        }
        for bad in ["Inside", "under_root", ""] {
            assert!(backup_check_drive_mutation(bad.to_string(), None, "write".to_string()).is_err());
            assert!(backup_check_app_mutation(bad.to_string(), "create".to_string()).is_err());
        }
    }

    /// The position helper and the words, against the shared vector.
    #[test]
    fn uniffi_backup_positions_and_names_match_core() {
        let (mut positions, mut names) = (0, 0);
        for case in vector_cases("backup_protect") {
            match case["kind"].as_str().unwrap() {
                "position" => {
                    let depth = case["depth"].as_u64().map(|d| u32::try_from(d).unwrap());
                    let name = case["name"].as_str().unwrap().to_string();
                    assert_eq!(
                        backup_position_at_depth(depth, name.clone()),
                        case["expected"],
                        "{}",
                        case["id"]
                    );
                    assert_eq!(backup_is_hidden_item(depth, name), case["hidden"], "{}", case["id"]);
                    positions += 1;
                }
                "names" => {
                    assert_eq!(backup_root_name(), case["root_name"]);
                    assert_eq!(backup_root_badge(), case["badge"]);
                    assert_eq!(backup_origin_header().name, case["origin_header"]);
                    assert_eq!(backup_origin_header().value, case["origin_backup"]);
                    names += 1;
                }
                _ => {}
            }
        }
        assert_eq!(
            (positions, names),
            (11, 1),
            "11 positions by depth and name; one names case"
        );
    }

    /// Plan Amendment 1, item 3: an unknown string is an error, never a pass.
    #[test]
    fn uniffi_backup_unknown_strings_are_errors() {
        let root = Some("backups_root".to_string());
        for bad in ["Trash", "erase", "", "delete "] {
            assert!(
                backup_check_root_mutation(root.clone(), bad.to_string()).is_err(),
                "mutation {bad:?}"
            );
            assert!(
                backup_check_root_mutation(None, bad.to_string()).is_err(),
                "mutation {bad:?} without a role"
            );
        }
        assert!(backup_check_root_mutation(Some("Backups".to_string()), "trash".to_string()).is_err());
        assert_eq!(
            backup_check_root_mutation(Some(String::new()), "trash".to_string()).unwrap(),
            None
        );
        let me = |platform: &str| BackupDeviceSelf {
            device_id: Uuid::nil().to_string(),
            name: "GLegion".to_string(),
            platform: platform.to_string(),
        };
        assert!(backup_find_device_folder(me("Windows"), Vec::new()).is_err());
        assert!(backup_find_device_folder(me("windows"), Vec::new()).is_ok());
        let record = |state: &str| BackupRecordEntry {
            key: "a.jpg".to_string(),
            size: 1,
            modified_ms: 1,
            remote_id: Uuid::nil().to_string(),
            uploaded_at_ms: 2,
            state: state.to_string(),
        };
        assert!(
            backup_plan_pass(
                Vec::new(),
                vec![record("BackedUp")],
                Vec::new(),
                true,
                Vec::new(),
                Vec::new(),
                1,
                1
            )
            .is_err()
        );
        assert!(
            backup_plan_pass(
                Vec::new(),
                vec![record("backed_up")],
                Vec::new(),
                true,
                Vec::new(),
                Vec::new(),
                1,
                1
            )
            .is_ok()
        );
    }

    /// Review 4 #3 and #7 through the binding iOS calls: a mark carries the
    /// remote id its record named (for a compare-and-set), and a budget of 0
    /// uploads still plans the first.
    #[test]
    fn uniffi_backup_plan_pass_marks_by_ref_and_never_stalls() {
        let id = Uuid::from_u128(7).to_string();
        let record = BackupRecordEntry {
            key: "gone.jpg".to_string(),
            size: 1,
            modified_ms: 1,
            remote_id: id.clone(),
            uploaded_at_ms: 2,
            state: "backed_up".to_string(),
        };
        let entry = |key: &str| BackupSourceEntry {
            key: key.to_string(),
            is_dir: false,
            size: 3,
            modified_ms: 4,
        };
        let plan = backup_plan_pass(
            vec![entry("a.jpg"), entry("b.jpg")],
            vec![record],
            Vec::new(),
            true,
            Vec::new(),
            Vec::new(),
            0,
            u64::MAX,
        )
        .expect("plan");
        assert_eq!(
            plan.mark_removed_elsewhere,
            [BackupRecordRef {
                key: "gone.jpg".to_string(),
                remote_id: id
            }]
        );
        assert_eq!((plan.uploads.len(), plan.deferred), (1, 1));
    }

    /// Review #6 and #7: a candidate whose manifest does not parse is not
    /// mine and not adoptable, and never fails the call; a legacy non-UUID id
    /// is matched as the device's own.
    #[test]
    fn uniffi_backup_unreadable_manifest_never_fails_the_call() {
        let me = || BackupDeviceSelf {
            device_id: "legacy-device-7".to_string(),
            name: "GLegion".to_string(),
            platform: "windows".to_string(),
        };
        let folder = |n: u128, name: &str, manifest: Option<&str>| BackupDeviceFolderCandidate {
            folder_id: Uuid::from_u128(n).to_string(),
            name: name.to_string(),
            manifest_json: manifest.map(str::to_string),
        };
        // Half-written: only a document that is not a JSON object is
        // unreadable (a bad field is read leniently, delta 3 #7).
        let broken = r#"{"version": 1, "device_id": "legacy-dev"#;
        let mine = r#"{"version": 1, "device_id": "legacy-device-7", "device_name": "GLegion"}"#;
        assert_eq!(
            backup_find_device_folder(me(), vec![folder(1, "GLegion", Some(broken))]).expect("no error"),
            BackupDeviceFolderChoice::Create {
                name: "GLegion (6c65)".to_string()
            },
            "an unreadable manifest is not adopted and its name is taken"
        );
        assert_eq!(
            backup_find_device_folder(
                me(),
                vec![folder(1, "GLegion", Some(broken)), folder(2, "Old name", Some(mine))]
            )
            .expect("no error"),
            BackupDeviceFolderChoice::Existing {
                folder_id: Uuid::from_u128(2).to_string()
            }
        );
    }

    /// The real iOS manifest vector round-trips through the DTO.
    #[test]
    fn uniffi_backup_manifest_round_trips() {
        let cases = vector_cases("backup_device");
        let case = cases
            .iter()
            .find(|c| c["id"] == "manifest_real_ios_round_trips")
            .expect("ios manifest case");
        let json = case["json"].as_str().unwrap();
        let dto = backup_parse_manifest(json.to_string()).expect("parse");
        assert_eq!(dto.platform, None);
        assert_eq!(dto.device_name, "Example iPhone");
        let sorted = serde_json::from_str::<serde_json::Value>(json).unwrap().to_string();
        assert_eq!(backup_serialize_manifest(dto).expect("serialize"), sorted);
    }

    /// Every manifest vector writes back what core writes through the DTO, a
    /// folder's unknown fields included (delta 3 #7).
    #[test]
    fn uniffi_backup_manifest_vectors_write_back_through_the_dto() {
        let mut checked = 0;
        for case in vector_cases("backup_device").iter().filter(|c| c["kind"] == "manifest") {
            let json = case["json"].as_str().unwrap();
            let written = case["expect"]["written"].as_str().unwrap_or(json);
            let sorted = serde_json::from_str::<serde_json::Value>(written).unwrap().to_string();
            let dto = backup_parse_manifest(json.to_string()).expect("parse");
            assert_eq!(
                backup_serialize_manifest(dto).expect("serialize"),
                sorted,
                "{}",
                case["id"]
            );
            checked += 1;
        }
        assert_eq!(checked, 10, "every manifest vector");
        let mut dto = backup_parse_manifest(r#"{"folders":[{"category":"pictures"}]}"#.to_string()).expect("parse");
        dto.folders[0].other_json = "[1]".to_string();
        assert!(
            backup_serialize_manifest(dto).is_err(),
            "a folder's other_json must be an object"
        );
    }

    /// A flat listing becomes the tree core merges.
    #[test]
    fn uniffi_backup_plan_merge_from_flat_rows() {
        let id = |n: u128| Uuid::from_u128(n).to_string();
        let row = |n: u128, parent: Option<u128>, name: &str, is_folder: bool| BackupMergeEntry {
            id: id(n),
            parent_id: parent.map(id),
            name: name.to_string(),
            is_folder,
        };
        let survivor = vec![row(1, None, "Backups", true), row(10, Some(1), "IMG_1.heic", false)];
        let duplicate = vec![
            row(2, None, "Backups", true),
            row(20, Some(2), "iPhone", true),
            row(21, Some(20), "a.heic", false),
            row(22, Some(2), "IMG_1.heic", false),
        ];
        let steps =
            backup_plan_merge(survivor, vec![duplicate], "merged".to_string(), "14.05".to_string()).expect("plan");
        assert_eq!(
            steps,
            [
                BackupMergeStep::Move {
                    id: id(20),
                    new_parent: id(1)
                },
                BackupMergeStep::MoveRenamed {
                    id: id(22),
                    new_parent: id(1),
                    new_name: "IMG_1 (merged, 14.05).heic".to_string(),
                },
                BackupMergeStep::Trash { id: id(2) },
            ]
        );
        let orphan = vec![row(3, None, "Backups", true), row(30, Some(99), "x", false)];
        assert!(
            backup_plan_merge(
                vec![row(1, None, "Backups", true)],
                vec![orphan],
                String::new(),
                String::new()
            )
            .is_err()
        );
        let two_roots = vec![row(4, None, "Backups", true), row(5, None, "Backups", true)];
        assert!(backup_plan_merge(two_roots, Vec::new(), String::new(), String::new()).is_err());
    }
}
