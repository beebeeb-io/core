//! Entry names and paths (spec §6.1), one function per step group.
//!
//! [`decode_name`] turns an entry's raw name bytes into text (step 1) and
//! NFC-normalises it (step 2); it never fails, so an undecodable name never
//! fails a listing. [`entry_path`] applies steps 3–8 and 12 and either gives
//! the components extraction writes or the reason the entry is skipped.
//! Clashes between names (step 9) are the planner's.

use unicode_normalization::UnicodeNormalization;

use super::limits::{MAX_COMPONENT_BYTES, MAX_DEPTH, MAX_PATH_BYTES};
use super::model::SkipReason;
use crate::path_safety::{archive_component, is_bidi_control};

/// An entry's raw name, as its format stores it.
#[derive(Debug, Clone, Copy)]
pub enum RawName<'a> {
    Zip {
        raw: &'a [u8],
        /// General-purpose bit 11: the name is UTF-8.
        utf8_flag: bool,
        /// The Info-ZIP Unicode Path extra field (0x7075): the CRC-32 of
        /// the raw name it was made for, and its UTF-8 name.
        unicode_path: Option<(u32, &'a [u8])>,
    },
    Tar {
        pax_path: Option<&'a [u8]>,
        gnu_long: Option<&'a [u8]>,
        /// The ustar prefix field (NUL-padded).
        prefix: &'a [u8],
        /// The name field (NUL-padded).
        name: &'a [u8],
    },
}

/// An entry path that is safe to create below the destination folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryPath {
    pub components: Vec<String>,
}

impl EntryPath {
    /// The path as the listing shows it: components joined by `/`.
    pub fn joined(&self) -> String {
        self.components.join("/")
    }
}

/// Step 1 and 2: decode the raw name, then NFC. Never fails.
///
/// - zip: UTF-8 when bit 11 is set (invalid bytes become U+FFFD, which
///   [`entry_path`] refuses); else the Unicode Path extra field when its
///   CRC matches the raw name; else UTF-8 when the raw bytes are valid UTF-8
///   with a byte ≥ 0x80 (older macOS wrote UTF-8 without the flag); else
///   CP437.
/// - tar: the pax `path`; else a GNU long name; else prefix + name; each as
///   UTF-8 when valid, else ISO-8859-1.
pub fn decode_name(raw: RawName<'_>) -> String {
    let text = match raw {
        RawName::Zip {
            raw, utf8_flag: true, ..
        } => String::from_utf8_lossy(raw).into_owned(),
        RawName::Zip { raw, unicode_path, .. } => {
            let from_extra = unicode_path
                .filter(|(crc, _)| *crc == crc32(raw))
                .and_then(|(_, name)| std::str::from_utf8(name).ok())
                .map(str::to_owned);
            match from_extra {
                Some(name) => name,
                None => match std::str::from_utf8(raw) {
                    Ok(text) if raw.iter().any(|&b| b >= 0x80) => text.to_owned(),
                    _ => decode_cp437(raw),
                },
            }
        }
        RawName::Tar {
            pax_path: Some(path), ..
        } => utf8_or_latin1(path),
        RawName::Tar {
            gnu_long: Some(long), ..
        } => utf8_or_latin1(until_nul(long)),
        RawName::Tar { prefix, name, .. } => {
            let (prefix, name) = (until_nul(prefix), until_nul(name));
            if prefix.is_empty() {
                utf8_or_latin1(name)
            } else {
                utf8_or_latin1(&[prefix, b"/", name].concat())
            }
        }
    };
    text.nfc().collect()
}

/// Steps 3–8 and 12: the components extraction writes, or why it skips.
pub fn entry_path(decoded: &str) -> Result<EntryPath, SkipReason> {
    // Step 3: a NUL, or a name core could not decode (U+FFFD), is never a
    // name. Control characters in a component are refused below.
    if decoded.contains('\0') || decoded.contains('\u{FFFD}') {
        return Err(SkipReason::UnusableName);
    }
    // Step 4: both separators split, in every format.
    let mut parts: Vec<&str> = decoded.split(['/', '\\']).collect();
    // Step 5: absolute paths become relative. `//server/share/` loses its
    // server and share; a leading separator its empty component (dropped
    // below); a drive prefix (`C:`, `C:x`) its letter and colon.
    if parts.len() >= 4 && parts[0].is_empty() && parts[1].is_empty() {
        parts.drain(..4);
    }
    if let Some(first) = parts.iter_mut().find(|p| !p.is_empty()) {
        let bytes = first.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            *first = &first[2..];
        }
    }
    // Step 6: any `..` is zip-slip, skipped and reported, never rewritten;
    // `.` and empty components are dropped.
    if parts.contains(&"..") {
        return Err(SkipReason::OutsideFolder);
    }
    parts.retain(|p| !p.is_empty() && *p != ".");
    if parts.is_empty() {
        return Err(SkipReason::UnusableName);
    }
    // Step 12: macOS resource forks.
    if parts[0] == "__MACOSX" {
        return Err(SkipReason::MacResource);
    }
    // Step 3 (per component) and 7: the portable archive rule.
    let mut components = Vec::with_capacity(parts.len());
    for part in parts {
        if part.chars().any(char::is_control) {
            return Err(SkipReason::UnusableName);
        }
        let component = archive_component(part).map_err(|_| SkipReason::UnusableName)?;
        // Step 8: the per-component limit.
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(SkipReason::UnusableName);
        }
        components.push(component);
    }
    // Step 8: depth and whole-path limits.
    let path_bytes = components.iter().map(String::len).sum::<usize>() + components.len() - 1;
    if components.len() > MAX_DEPTH || path_bytes > MAX_PATH_BYTES {
        return Err(SkipReason::UnusableName);
    }
    Ok(EntryPath { components })
}

/// A name as the listing shows it: the decoded text with every control
/// character, and every bidi override or isolate, shown as U+FFFD, so a
/// hostile name cannot move the cursor, break a line, or show
/// `photo\u{202e}gpj.exe` as `photoexe.jpg` on screen.
pub fn display_name(decoded: &str) -> String {
    decoded
        .chars()
        .map(|c| {
            if c.is_control() || is_bidi_control(c) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

fn until_nul(field: &[u8]) -> &[u8] {
    field.iter().position(|&b| b == 0).map_or(field, |end| &field[..end])
}

fn utf8_or_latin1(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => bytes.iter().map(|&b| char::from(b)).collect(),
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}

/// CP437's upper half (0x80–0xFF); the lower half is ASCII.
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', //
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', //
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', //
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', //
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', //
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', //
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', //
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// Bytes as CP437 text.
pub(crate) fn decode_cp437(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                char::from(b)
            } else {
                CP437_HIGH[usize::from(b - 0x80)]
            }
        })
        .collect()
}

/// Text as CP437 bytes (wiped when dropped: a password passes through
/// here), or `None` when a character has no CP437 byte.
pub(crate) fn encode_cp437(text: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(text.len()));
    for c in text.chars() {
        let byte = if c.is_ascii() {
            c as u8
        } else {
            0x80 + CP437_HIGH.iter().position(|&h| h == c)? as u8
        };
        out.push(byte);
    }
    Some(out)
}
