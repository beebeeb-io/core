//! Device folders: the name, the device id and which folder is mine (spec
//! §4.2 rules 2 and 3).

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use beebeeb_types::backup::Platform;

use super::fold_name;
use super::manifest::DeviceManifest;
use crate::invisible::{is_invisible_filler, is_stripped_display_control};
use crate::path_safety::{check_component_for, is_windows_reserved_stem};

/// The SHA-256 domain prefix of the desktop device id (not a key: the id is
/// an identifier, only ever stored inside the encrypted manifest).
pub const DEVICE_ID_LABEL: &[u8] = b"beebeeb/backup-device-id/v1";

/// The folder name when the platform's name has nothing usable in it.
const FALLBACK_NAME: &str = "Device";

/// The longest device name kept, in UTF-8 bytes, so a suffixed name still fits
/// one path component.
const NAME_MAX_BYTES: usize = 200;

/// Derive a desktop's device id from the OS's stable machine id (Windows
/// `MachineGuid`, macOS `IOPlatformUUID`, Linux `/etc/machine-id`), so a
/// reinstall keeps its id: SHA-256(`DEVICE_ID_LABEL` || 0x00 || trimmed id),
/// the first 16 bytes, with the RFC 4122 version-8 and variant bits set. The
/// raw machine id never leaves the device.
pub fn device_id_from_machine_id(machine_id: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_ID_LABEL);
    hasher.update([0u8]);
    hasher.update(machine_id.trim().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// A name already used under the Backups root, and the device id from its
/// manifest (`None` when it has no manifest, or one without an id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakenName {
    pub name: String,
    pub device_id: Option<Uuid>,
}

/// The person-facing name made safe for one path component on every
/// platform. Separators, control characters and the characters Windows
/// refuses become `_`; display controls (bidi, zero-width) are removed;
/// trailing dots and spaces become `_`; a reserved Windows name gets `_` after
/// its stem. A name with nothing visible left of the original is `"Device"`.
fn clean_name(raw: &str) -> String {
    // (char, came from the original unchanged)
    let mut out: Vec<(char, bool)> = Vec::with_capacity(raw.len());
    for c in raw.nfc() {
        if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            out.push(('_', false));
        } else if !is_stripped_display_control(c) {
            out.push((c, true));
        }
    }
    let mut bytes = 0;
    out.retain(|(c, _)| {
        bytes += c.len_utf8();
        bytes <= NAME_MAX_BYTES
    });
    for slot in out.iter_mut().rev() {
        if slot.0 != '.' && slot.0 != ' ' {
            break;
        }
        *slot = ('_', false);
    }
    let visible = out
        .iter()
        .any(|(c, original)| *original && !c.is_whitespace() && !is_invisible_filler(*c));
    if !visible {
        return FALLBACK_NAME.to_string();
    }
    let mut name: String = out.into_iter().map(|(c, _)| c).collect();
    if is_windows_reserved_stem(&name) {
        let stem_end = name.find('.').unwrap_or(name.len());
        let stem_end = name[..stem_end].trim_end().len();
        name.insert(stem_end, '_');
    }
    if check_component_for(&name, true, true).is_err() {
        return FALLBACK_NAME.to_string();
    }
    name
}

fn taken_by_another(name: &str, my_id: Uuid, taken: &[TakenName]) -> bool {
    let folded = fold_name(name);
    taken
        .iter()
        .any(|t| t.device_id != Some(my_id) && fold_name(&t.name) == folded)
}

/// The device folder name for `raw` (the platform's user-facing computer or
/// device name). When another device already uses the name (its manifest has a
/// different id, or it has none), the first 4 hex digits of `my_id` are added:
/// `GLegion (a3f2)`; if that is taken too, the suffix widens 4 digits at a time.
pub fn device_folder_name(raw: &str, my_id: Uuid, taken: &[TakenName]) -> String {
    let base = clean_name(raw);
    if !taken_by_another(&base, my_id, taken) {
        return base;
    }
    let hex = my_id.simple().to_string();
    let mut width = 4;
    loop {
        let candidate = format!("{base} ({})", &hex[..width]);
        if width == hex.len() || !taken_by_another(&candidate, my_id, taken) {
            return candidate;
        }
        width += 4;
    }
}

/// This device, as the identity rule sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSelf {
    pub device_id: Uuid,
    /// The platform's user-facing name (before [`device_folder_name`]).
    pub name: String,
    pub platform: Platform,
}

/// One folder directly under the Backups root, with its manifest when it has
/// one (decrypted and parsed by the client).
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceFolderCandidate {
    pub folder_id: Uuid,
    pub name: String,
    pub manifest: Option<DeviceManifest>,
}

/// Which folder this device backs up into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceFolderChoice {
    /// The folder whose manifest has my device id.
    Existing(Uuid),
    /// The old desktop mirror's folder (my exact name, no manifest at all).
    /// The client writes the manifest at once.
    AdoptLegacy(Uuid),
    /// No folder is mine: create one with this name.
    Create { name: String },
}

fn is_desktop(platform: Platform) -> bool {
    matches!(platform, Platform::Windows | Platform::Macos | Platform::Linux)
}

/// Spec §4.2 rule 3, in order: (a) the folder whose manifest has my id; (b)
/// for a desktop only, a folder with my exact (unsuffixed) name and no
/// manifest, which only the old desktop mirror ever wrote; (c) a new folder,
/// named by [`device_folder_name`]. A tie is broken by the smallest folder id,
/// so every listing order gives the same answer.
pub fn find_device_folder(me: &DeviceSelf, candidates: &[DeviceFolderCandidate]) -> DeviceFolderChoice {
    let mine = candidates
        .iter()
        .filter(|c| c.manifest.as_ref().and_then(|m| m.device_id) == Some(me.device_id))
        .map(|c| c.folder_id)
        .min();
    if let Some(id) = mine {
        return DeviceFolderChoice::Existing(id);
    }
    if is_desktop(me.platform) {
        let legacy_name = device_folder_name(&me.name, me.device_id, &[]);
        let legacy = candidates
            .iter()
            .filter(|c| c.manifest.is_none() && c.name.nfc().eq(legacy_name.chars()))
            .map(|c| c.folder_id)
            .min();
        if let Some(id) = legacy {
            return DeviceFolderChoice::AdoptLegacy(id);
        }
    }
    let taken: Vec<TakenName> = candidates
        .iter()
        .map(|c| TakenName {
            name: c.name.clone(),
            device_id: c.manifest.as_ref().and_then(|m| m.device_id),
        })
        .collect();
    DeviceFolderChoice::Create {
        name: device_folder_name(&me.name, me.device_id, &taken),
    }
}
