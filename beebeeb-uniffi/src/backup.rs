//! The backup rules for iOS (and later Android): LD-0113, spec
//! `2026-11-06-backup-from-source-design.md` §4.4. Every function forwards to
//! `beebeeb_core::backup`; no rule lives here. Ids and keys cross as strings.
//! Any string this side must parse (a mutation, a role, a platform, a record
//! state, an id) that it does not know is `CryptoError::InvalidInput`, never a
//! pass (plan Amendment 1, item 3). Split out of `lib.rs`, which is over the
//! file-size ratchet.

use std::collections::{HashMap, HashSet};

use beebeeb_core::backup as rules;
use beebeeb_types::backup::{Platform, SystemRole};
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

/// The words to show when `mutation` (`"trash" | "delete" | "rename" |
/// "move"`) of a row with `role` is refused, or `None` when it is allowed.
#[uniffi::export]
pub fn backup_check_mutation(role: Option<String>, mutation: String) -> Result<Option<String>, CryptoError> {
    let m = rules::Mutation::parse(&mutation).ok_or_else(|| invalid("unknown mutation"))?;
    Ok(rules::check_mutation(parse_role(role.as_deref())?, m)
        .err()
        .map(|p| p.message.to_string()))
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
    let taken = taken
        .into_iter()
        .map(|t| {
            Ok(rules::TakenName {
                name: t.name,
                device_id: t.device_id.as_deref().map(|d| parse_id("device_id", d)).transpose()?,
            })
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    Ok(rules::device_folder_name(&raw, parse_id("my_id", &my_id)?, &taken))
}

#[derive(uniffi::Record)]
pub struct BackupDeviceSelf {
    pub device_id: String,
    pub name: String,
    /// `"windows" | "macos" | "linux" | "ios" | "android" | "cli"`.
    pub platform: String,
}

#[derive(uniffi::Record)]
pub struct BackupDeviceFolderCandidate {
    pub folder_id: String,
    pub name: String,
    /// The decrypted `.device.json`, `None` when the folder has none. A
    /// manifest that does not parse is an error, never "no manifest".
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
    let me = rules::DeviceSelf {
        device_id: parse_id("device_id", &me.device_id)?,
        name: me.name,
        platform: parse_platform(&me.platform)?,
    };
    let candidates = candidates
        .into_iter()
        .map(|c| {
            Ok(rules::DeviceFolderCandidate {
                folder_id: parse_id("folder_id", &c.folder_id)?,
                name: c.name,
                manifest: c.manifest_json.as_deref().map(rules::parse_manifest).transpose()?,
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

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupFolderState {
    pub category: String,
    pub enabled: bool,
    pub last_pass_at_ms: Option<i64>,
    pub items: u64,
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
        device_id: m.device_id.map(|id| id.to_string()),
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
            })
            .collect(),
        other_json: serde_json::Value::Object(m.other).to_string(),
    })
}

#[uniffi::export]
pub fn backup_serialize_manifest(manifest: BackupDeviceManifest) -> Result<String, CryptoError> {
    let other = match serde_json::from_str::<serde_json::Value>(&manifest.other_json) {
        Ok(serde_json::Value::Object(other)) => other,
        _ => return Err(invalid("other_json must be a JSON object")),
    };
    let m = rules::DeviceManifest {
        version: manifest.version,
        device_id: manifest
            .device_id
            .as_deref()
            .map(|d| parse_id("device_id", d))
            .transpose()?,
        device_name: manifest.device_name,
        platform: manifest.platform.as_deref().map(parse_platform).transpose()?,
        folders: manifest
            .folders
            .into_iter()
            .map(|f| rules::FolderState {
                category: f.category,
                enabled: f.enabled,
                last_pass_at_ms: f.last_pass_at_ms,
                items: f.items,
            })
            .collect(),
        other,
    };
    Ok(rules::serialize_manifest(&m))
}

// ── The pass planner ───────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct BackupSourceEntry {
    /// On iOS: the asset id.
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
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupPlannedMove {
    pub remote_id: String,
    pub from_key: String,
    pub to_key: String,
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupPassPlan {
    pub uploads: Vec<BackupPlannedUpload>,
    pub moves: Vec<BackupPlannedMove>,
    pub folders: Vec<String>,
    pub mark_removed_elsewhere: Vec<String>,
    pub unchanged: u64,
    pub gone_locally: u64,
    pub deferred: u64,
}

fn parse_state(s: &str) -> Result<rules::RecordState, CryptoError> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|_| invalid("unknown record state"))
}

/// `unseen`: keys the source did not look at or into (iOS passes an empty
/// list). `max_uploads` saturates at the platform's `usize`.
#[uniffi::export]
pub fn backup_plan_pass(
    entries: Vec<BackupSourceEntry>,
    records: Vec<BackupRecordEntry>,
    live_remote: Vec<String>,
    unseen: Vec<String>,
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
    let plan = rules::plan_pass(&entries, &records, &live, &unseen, budget);
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
        mark_removed_elsewhere: plan.mark_removed_elsewhere,
        unchanged: plan.unchanged as u64,
        gone_locally: plan.gone_locally as u64,
        deferred: plan.deferred as u64,
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

    /// The shared protection matrix through the binding iOS calls.
    #[test]
    fn uniffi_backup_check_mutation_matches_core() {
        let mut matrix = 0;
        for case in vector_cases("backup_protect")
            .iter()
            .filter(|c| c["kind"] == "mutation")
        {
            let role = case["role"].as_str().map(str::to_string);
            let got =
                backup_check_mutation(role, case["mutation"].as_str().unwrap().to_string()).expect("known strings");
            let want = match case["expect"].as_str().unwrap() {
                "ok" => None,
                words => Some(words.to_string()),
            };
            assert_eq!(got, want, "{}", case["id"]);
            if ["root", "child", "other"].contains(&case["target"].as_str().unwrap()) {
                matrix += 1;
            }
        }
        assert_eq!(matrix, 12, "the 4 x 3 matrix");
    }

    /// Plan Amendment 1, item 3: an unknown string is an error, never a pass.
    #[test]
    fn uniffi_backup_unknown_strings_are_errors() {
        let root = Some("backups_root".to_string());
        for bad in ["Trash", "erase", "", "delete "] {
            assert!(
                backup_check_mutation(root.clone(), bad.to_string()).is_err(),
                "mutation {bad:?}"
            );
            assert!(
                backup_check_mutation(None, bad.to_string()).is_err(),
                "mutation {bad:?} without a role"
            );
        }
        assert!(backup_check_mutation(Some("Backups".to_string()), "trash".to_string()).is_err());
        assert_eq!(
            backup_check_mutation(Some(String::new()), "trash".to_string()).unwrap(),
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
        assert!(backup_plan_pass(Vec::new(), vec![record("BackedUp")], Vec::new(), Vec::new(), 1, 1).is_err());
        assert!(backup_plan_pass(Vec::new(), vec![record("backed_up")], Vec::new(), Vec::new(), 1, 1).is_ok());
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
