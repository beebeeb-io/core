//! Every word the archive screens show (spec §9), in one place.
//!
//! A word is an [`ArchiveText`]: a stable key, the English source text, and
//! the unsubstituted arguments, so a client with an i18n layer (web) can
//! translate and every other client shows `text`. Plurals are core's.
//!
//! The templates use two forms: `{name}` is replaced by the argument, and
//! `{name|one|other}` becomes `one` when the argument is exactly `"1"` and
//! `other` otherwise. The cross-client vectors pin the result byte for byte.

use serde::Serialize;

/// A word: its key, the English text, and the arguments it was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveText {
    pub key: &'static str,
    pub text: String,
    pub args: Vec<(String, String)>,
}

macro_rules! archive_keys {
    ($($variant:ident => $key:literal, $template:literal;)+) => {
        /// One variant per spec §9 key.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ArchiveKey {
            $($variant,)+
        }

        impl ArchiveKey {
            /// Every key, in spec §9 order.
            pub const ALL: [ArchiveKey; archive_keys!(@count $($variant)+)] = [$(ArchiveKey::$variant,)+];

            /// The stable message key.
            pub const fn key(self) -> &'static str {
                match self {
                    $(ArchiveKey::$variant => $key,)+
                }
            }

            /// The English source template.
            const fn template(self) -> &'static str {
                match self {
                    $(ArchiveKey::$variant => $template,)+
                }
            }

            /// The key for a stable message key string.
            pub fn parse(key: &str) -> Option<Self> {
                Self::ALL.into_iter().find(|k| k.key() == key)
            }
        }
    };
    (@count) => { 0 };
    (@count $head:ident $($tail:ident)*) => { 1 + archive_keys!(@count $($tail)*) };
}

archive_keys! {
    ArchiveReading => "archive_reading", "Reading the archive\u{2026}";
    ArchiveKindZip => "archive_kind_zip", "ZIP archive";
    ArchiveKindTar => "archive_kind_tar", "TAR archive";
    ArchiveKindTgz => "archive_kind_tgz", "TAR archive, gzip-compressed";
    ArchiveKindGz => "archive_kind_gz", "gzip-compressed file";
    ArchiveSummary => "archive_summary", "{files} {files|file|files}, {folders} {folders|folder|folders} \u{b7} {size}";
    ArchiveEmpty => "archive_empty", "This archive is empty.";
    ArchiveSomeProtected => "archive_some_protected", "Some files in this archive are protected by a password.";
    ArchiveAllProtected => "archive_all_protected", "The files in this archive are protected by a password.";
    ArchiveNamesNotProtected => "archive_names_not_protected", "The password protects the files' contents, not their names.";
    ArchiveZipcryptoWeak => "archive_zipcrypto_weak", "This archive uses ZipCrypto, an old protection that can be broken without the password. Files you extract are stored with Beebeeb's own encryption.";
    ArchiveListingIncomplete => "archive_listing_incomplete", "This archive is too large to list here. Extract it to see all its files.";
    EntryLink => "entry_link", "Link, not extracted";
    EntryDevice => "entry_device", "Special file, not extracted";
    EntryOutside => "entry_outside", "Points outside the folder, not extracted";
    EntryBadName => "entry_bad_name", "Name can't be used, not extracted";
    EntryMethod => "entry_method", "Uses {method} compression, which Beebeeb can't open";
    EntryTooLarge => "entry_too_large", "Too large to extract here";
    EntryBomb => "entry_bomb", "Expands far more than a normal file, not extracted";
    EntryMacResource => "entry_mac_resource", "macOS resource data, not extracted";
    EntryUnsupported => "entry_unsupported", "{what}, not extracted";
    EntryCorrupt => "entry_corrupt", "Damaged in the archive, not extracted";
    EntryOtherPassword => "entry_other_password", "Uses a different password, not extracted";
    EntryRenamed => "entry_renamed", "Saved as \"{name}\"";
    ActionExtract => "action_extract", "Extract";
    ActionExtractTo => "action_extract_to", "Extract to\u{2026}";
    ActionExtractSelected => "action_extract_selected", "Extract {n} {n|item|items}";
    ActionDownload => "action_download", "Download";
    ActionOpen => "action_open", "Open";
    ActionStop => "action_stop", "Stop";
    ActionOpenFolder => "action_open_folder", "Open folder";
    ActionMoveToTrash => "action_move_to_trash", "Move to Trash";
    ActionCancel => "action_cancel", "Cancel";
    PasswordTitle => "password_title", "Enter the archive's password";
    PasswordBody => "password_body", "\"{name}\" is protected by a password. Beebeeb uses it on this device only and doesn't keep it.";
    PasswordWrong => "password_wrong", "That password didn't work. Check it and try again.";
    ExtractProgress => "extract_progress", "Extracting {done} of {total} {total|file|files} \u{b7} {bytes_done} of {bytes_total}";
    ExtractKeepOpen => "extract_keep_open", "Keep Beebeeb open until extraction finishes.";
    ExtractDone => "extract_done", "Extracted {files} {files|file|files} to \"{folder}\".";
    ExtractDoneWithSkips => "extract_done_with_skips", "Extracted {files} {files|file|files} to \"{folder}\". {skipped} {skipped|was|were} not extracted; the list says why.";
    ExtractRenamed => "extract_renamed", "{n} {n|file|files} had the same name as another file and {n|was|were} renamed.";
    ExtractStopped => "extract_stopped", "Extraction stopped. {done} of {total} {total|file is|files are} in \"{folder}\"; the rest were not extracted.";
    ExtractFailedStorageFull => "extract_failed_storage_full", "Your storage is full. {done} of {total} {total|file was|files were} extracted to \"{folder}\".";
    ExtractFailedNetwork => "extract_failed_network", "The connection was lost. {done} of {total} {total|file was|files were} extracted to \"{folder}\".";
    ExtractFailedDamaged => "extract_failed_damaged", "The archive is damaged after {done} of {total} {total|file|files}. {done|That file is|Those files are} in \"{folder}\".";
    ExtractFailedChanged => "extract_failed_changed", "The archive changed while it was being extracted. {done} of {total} {total|file is|files are} in \"{folder}\". Open it again to extract the new version.";
    RefuseNotArchive => "refuse_not_archive", "This file isn't an archive Beebeeb can open. Beebeeb opens ZIP, TAR, TGZ and GZ files.";
    RefuseForeign => "refuse_foreign", "This is a {format} archive. Beebeeb opens ZIP, TAR, TGZ and GZ files.";
    RefuseSfx => "refuse_sfx", "This is a self-extracting program, not a plain archive.";
    RefuseSpanned => "refuse_spanned", "This is one part of a multi-part archive. Beebeeb opens single-file archives only.";
    RefuseStrongEncryption => "refuse_strong_encryption", "This archive uses PKWARE strong encryption, which Beebeeb can't open.";
    RefuseDamaged => "refuse_damaged", "This archive is damaged and can't be read.";
    RefuseTruncated => "refuse_truncated", "This archive ends too early. It may not have finished uploading.";
    RefuseTooMany => "refuse_too_many", "This archive has more than 100,000 items, more than Beebeeb extracts at once.";
    RefuseTooLarge => "refuse_too_large", "This archive expands to {size}, more than Beebeeb extracts at once ({limit}).";
    RefuseBomb => "refuse_bomb", "This archive expands far more than normal archives do, so Beebeeb won't extract it.";
    RefuseQuota => "refuse_quota", "Extracting needs {needed} and you have {free} free.";
    RefuseDeviceSpace => "refuse_device_space", "Extracting needs {needed} free on this device, and it has {free}.";
    RefuseBackups => "refuse_backups", "Backups are read-only. Choose a folder outside Backups to extract to.";
    RefuseReadOnlyFolder => "refuse_read_only_folder", "You can't add files to this folder. Choose another folder to extract to.";
    RefuseWebEntryTooLarge => "refuse_web_entry_too_large", "{n} {n|file is|files are} larger than {limit}, more than the browser can extract. Extract the rest here, or use the Beebeeb app or bb extract for all of them.";
    CliPasswordNeeded => "cli_password_needed", "This archive needs a password. Run it in a terminal, or pass the password with --password-stdin.";
    CliExtractToHint => "cli_extract_to_hint", "Add --to <folder> to extract somewhere else.";
}

/// Build the word for `key` from its arguments. A placeholder whose
/// argument is missing stays as written (`{name}`), so a caller bug shows
/// on screen and in the vectors instead of an empty string.
pub fn archive_text(key: ArchiveKey, args: &[(&str, &str)]) -> ArchiveText {
    ArchiveText {
        key: key.key(),
        text: render(key.template(), args),
        args: args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }
}

fn render(template: &str, args: &[(&str, &str)]) -> String {
    let lookup = |name: &str| args.iter().find(|(k, _)| *k == name).map(|(_, v)| *v);
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let inner = &after[..close];
        let mut parts = inner.split('|');
        let name = parts.next().unwrap_or_default();
        match (parts.next(), parts.next(), lookup(name)) {
            (Some(one), Some(other), value) => out.push_str(if value == Some("1") { one } else { other }),
            (None, _, Some(value)) => out.push_str(value),
            _ => {
                out.push('{');
                out.push_str(inner);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// A count as the English text shows it: digits grouped by commas.
pub fn count_label(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A size as the archive screens show it: core's compact formatter at one
/// decimal (`3.2 MB`), the same for every client.
pub fn size_label(bytes: u64) -> String {
    beebeeb_types::format::format_compact(i64::try_from(bytes).unwrap_or(i64::MAX), 1)
}
