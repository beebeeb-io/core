//! The one conflict rule (move 13, spec §16.2).
//!
//! Ported from the desktop client (`src-tauri/src/conflict.rs` and
//! `engine_bridge::keep_both_name`): pure functions over versions, no I/O.
//! A file has a conflict when **both** sides moved past the last shared base
//! and they moved to different states. Core never auto-picks a winner;
//! auto-resolution is only the time-based "Keep Both" fallback after 24 h.
//!
//! Conflict decisions are consumed by [`super::engine::SyncEngine`].

use std::collections::HashSet;
use std::fmt;

/// Longest file name mainstream filesystems take, in UTF-8 bytes.
pub const MAX_NAME_BYTES: usize = 255;

/// The longest device name a "Keep Both" copy names, in UTF-8 bytes.
pub const KEEP_BOTH_DEVICE_MAX_BYTES: usize = 64;

/// A version identity obtained from authenticated file metadata.
///
/// The server's untrusted content hash is not a version identity. Callers must
/// open the file metadata first and pass its authenticated version commitment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedVersionId(String);

impl AuthenticatedVersionId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidVersionId> {
        let value = value.into();
        if value.is_empty() {
            Err(InvalidVersionId)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidVersionId;

impl fmt::Display for InvalidVersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authenticated version identity is empty")
    }
}

impl std::error::Error for InvalidVersionId {}

/// One side's authenticated view of a file at a given moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub authenticated_version: AuthenticatedVersionId,
    pub modified_at: u64,
}

/// `true` when both sides moved away from the last shared base AND landed on
/// different states.
pub fn is_conflict(local: &VersionInfo, remote: &VersionInfo, base: &VersionInfo) -> bool {
    local.authenticated_version != base.authenticated_version
        && remote.authenticated_version != base.authenticated_version
        && local.authenticated_version != remote.authenticated_version
}

/// Twenty-four hours after detection, in seconds since the Unix epoch.
pub fn auto_resolution_deadline(detected_at: u64) -> Option<u64> {
    detected_at.checked_add(24 * 3600)
}

/// Whether the 24 h fallback may fire now.
pub fn resolution_due(detected_at: u64, now: u64) -> bool {
    auto_resolution_deadline(detected_at).is_some_and(|deadline| now >= deadline)
}

/// The user's choice from the conflict window; the strings are the IPC values
/// `"local"` / `"remote"` / `"both"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Resolution {
    KeepLocal,
    KeepRemote,
    KeepBoth,
}

impl Resolution {
    /// The stable wire/name form (`local`/`remote`/`both`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeepLocal => "local",
            Self::KeepRemote => "remote",
            Self::KeepBoth => "both",
        }
    }
}

/// What a sync tick should do with one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictOutcome {
    /// Nothing diverged; apply normally.
    Clean,
    /// Diverged: wait for the user. Never pick a side.
    NeedsUser,
    /// Diverged and ignored for the whole window: materialise Keep Both.
    AutoKeepBoth,
}

impl ConflictOutcome {
    /// The stable wire/name form (`clean`/`needs_user`/`auto_keep_both`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::NeedsUser => "needs_user",
            Self::AutoKeepBoth => "auto_keep_both",
        }
    }
}

impl fmt::Display for ConflictOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The conflict policy: how long a conflict may wait before the fallback
/// materialises a Keep Both copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConflictPolicy {
    /// Seconds after detection before `AutoKeepBoth` may fire.
    pub auto_resolve_after_secs: u64,
}

impl ConflictPolicy {
    /// The shipped policy: 24 h.
    pub const DEFAULT: Self = Self {
        auto_resolve_after_secs: 24 * 3600,
    };

    /// Seconds-since-epoch deadline for a conflict detected at `detected_at`.
    pub fn deadline(&self, detected_at: u64) -> Option<u64> {
        detected_at.checked_add(self.auto_resolve_after_secs)
    }

    /// Whether the fallback may fire now.
    pub fn due(&self, detected_at: u64, now: u64) -> bool {
        self.deadline(detected_at).is_some_and(|deadline| now >= deadline)
    }

    /// Decide one file. `base = None` means no shared base is known: equal
    /// hashes are clean, different hashes are a conflict.
    pub fn resolve(
        &self,
        local: &VersionInfo,
        remote: &VersionInfo,
        base: Option<&VersionInfo>,
        detected_at: u64,
        now: u64,
    ) -> ConflictOutcome {
        let diverged = match base {
            Some(base) => is_conflict(local, remote, base),
            None => local.authenticated_version != remote.authenticated_version,
        };
        if !diverged {
            ConflictOutcome::Clean
        } else if self.due(detected_at, now) {
            ConflictOutcome::AutoKeepBoth
        } else {
            ConflictOutcome::NeedsUser
        }
    }
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// `name` split before its extension. A name that starts with a dot and has no
/// other dot has no extension (`.env`, not `"" + ".env"`).
fn split_extension(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(0) | None => (name, ""),
        Some(dot) => (&name[..dot], &name[dot..]),
    }
}

/// The longest prefix of `text` that fits in `max` bytes, cut at a character
/// boundary.
pub fn prefix_within(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The bytes `text`'s first character takes; 0 for empty text.
fn first_char_len(text: &str) -> usize {
    text.chars().next().map_or(0, char::len_utf8)
}

/// `<stem><suffix><.ext>`, the stem cut so the whole is at most
/// [`MAX_NAME_BYTES`]: the cut applies to the stem, never to the suffix and
/// never to the extension while it leaves room for the stem's first character.
pub fn with_suffix(name: &str, suffix: &str) -> String {
    let (stem, extension) = match split_extension(name) {
        (stem, extension) if extension.len() + suffix.len() + first_char_len(stem) > MAX_NAME_BYTES => (name, ""),
        split => split,
    };
    let room = MAX_NAME_BYTES.saturating_sub(suffix.len() + extension.len());
    format!("{}{suffix}{extension}", prefix_within(stem, room))
}

/// The device label as ONE safe path component: it can come from another
/// client, so a separator, control character or reserved device name in it must
/// not reach the file name. A value [`crate::path_safety::sanitize_component`]
/// refuses outright falls back to the literal `device` rather than failing the
/// Keep Both copy.
fn safe_device(device: &str) -> String {
    crate::path_safety::sanitize_component(device, crate::path_safety::Rules::Portable)
        .unwrap_or_else(|_| "device".to_string())
}

/// The name of the "Keep Both" copy: `{stem} ({device}, HH.MM){ext}`, then
/// `{stem} ({device}, HH.MM) 2{ext}`, ` 3`, ... until it is not in `taken`
/// (the parent's names, lowercased).
///
/// The time uses a dot, not a colon: a `:` in a Mac file name shows as `/` in
/// Finder. The device is cut to [`KEEP_BOTH_DEVICE_MAX_BYTES`] first, so the
/// suffix always leaves the stem room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKeepBothTime;

impl fmt::Display for InvalidKeepBothTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("time must be HH.MM from 00.00 through 23.59")
    }
}

impl std::error::Error for InvalidKeepBothTime {}

fn validate_hhmm(hhmm: &str) -> Result<(), InvalidKeepBothTime> {
    let bytes = hhmm.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b'.'
        || !bytes[0].is_ascii_digit()
        || !bytes[1].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
        || !bytes[4].is_ascii_digit()
    {
        return Err(InvalidKeepBothTime);
    }
    let hour = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
    let minute = (bytes[3] - b'0') * 10 + (bytes[4] - b'0');
    if hour > 23 || minute > 59 {
        return Err(InvalidKeepBothTime);
    }
    Ok(())
}

pub fn keep_both_name(
    original: &str,
    device: &str,
    hhmm: &str,
    taken: &HashSet<String>,
) -> Result<String, InvalidKeepBothTime> {
    validate_hhmm(hhmm)?;
    let device = safe_device(device);
    let device = prefix_within(&device, KEEP_BOTH_DEVICE_MAX_BYTES);
    let mut counter = 1u32;
    loop {
        let suffix = if counter == 1 {
            format!(" ({device}, {hhmm})")
        } else {
            format!(" ({device}, {hhmm}) {counter}")
        };
        let candidate = with_suffix(original, &suffix);
        if !taken.contains(&candidate.to_lowercase()) {
            return Ok(candidate);
        }
        counter = counter.saturating_add(1);
    }
}
