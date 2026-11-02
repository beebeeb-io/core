//! Share-link grammar (task C3-9, spec §16.2 move 9).
//!
//! One builder and one parser for the link every client mints:
//!
//! ```text
//! {app_url}/{s|f}/{token}#key={percent-encoded key}
//! ```
//!
//! `s` is a file/bundle share and `f` is a folder link. The fragment always
//! carries the client key `K_c`; the passphrase of a protected folder link
//! stretches the unwrap key and never replaces it.
//!
//! The two client encodings that exist today are both accepted:
//!
//! - the raw value handed to the builder is **not** reinterpreted: `build`
//!   percent-encodes it exactly like `encodeURIComponent`, so a base64url
//!   value (the current web and CLI links) is byte-identical to what those
//!   clients already emit;
//! - [`key_bytes`] decodes both standard base64 (legacy links, `+` `/` `=`)
//!   and base64url (current links, `-` `_`, optional padding), which is the
//!   rule mobile's `fragmentKeyToBytes` applies. A parser that understood
//!   only one alphabet would break the other client's links, so it
//!   understands both and changes neither.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Which route a share link lives on: `/s/` for a file or bundle share,
/// `/f/` for a folder link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareRoute {
    /// `/s/{token}` — a single file or bundle share.
    Single,
    /// `/f/{token}` — a folder link.
    Folder,
}

impl ShareRoute {
    /// The path segment this route uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "s",
            Self::Folder => "f",
        }
    }

    /// Parse the route segment; `None` for anything that is not `s` or `f`.
    pub fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "s" => Some(Self::Single),
            "f" => Some(Self::Folder),
            _ => None,
        }
    }
}

impl fmt::Display for ShareRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed share link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLink {
    /// Scheme, authority and any base path the link was minted under, with no
    /// trailing slash. A legacy host is kept as it was, never rewritten.
    pub base_url: String,
    /// `/s/` or `/f/`.
    pub route: ShareRoute,
    /// The public, unguessable share token.
    pub token: String,
    /// The percent-decoded `#key=` value, exactly as the builder handed it in.
    pub key: String,
}

impl ShareLink {
    /// The key as bytes; see [`key_bytes`].
    pub fn key_bytes(&self) -> Option<Vec<u8>> {
        key_bytes(&self.key)
    }
}

/// Why a string is not a share link. [`Self::code`] is the stable identifier a
/// client can branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareLinkError {
    /// The URL has no `#key=` fragment.
    MissingFragment,
    /// The fragment is not a non-empty `key=` value.
    MissingKey,
    /// The path carries no `{s|f}/{token}` pair.
    MissingToken,
    /// The string is not a URL, or its share segment is neither `s` nor `f`.
    NotAShareLink,
}

impl ShareLinkError {
    /// The stable identifier for this error.
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingFragment => "missing_fragment",
            Self::MissingKey => "missing_key",
            Self::MissingToken => "missing_token",
            Self::NotAShareLink => "not_a_share_link",
        }
    }
}

impl fmt::Display for ShareLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingFragment => "share link has no #key fragment",
            Self::MissingKey => "share link fragment is not a #key= value",
            Self::MissingToken => "share link path has no /s/ or /f/ token",
            Self::NotAShareLink => "not a share link",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ShareLinkError {}

/// Build a `/s/{token}#key=…` link.
///
/// This is the canonical single-file share form; `build_for` covers `/f/`.
pub fn build(app_url: &str, token: &str, key: &str) -> String {
    build_for(app_url, token, key, ShareRoute::Single)
}

/// Build a link on `route`, percent-encoding the fragment value exactly like
/// `encodeURIComponent`.
///
/// The key is taken as given: a base64url value stays byte-identical (its
/// characters are unreserved), and a standard-base64 value gains only the
/// `%` escapes that the clients already emit.
pub fn build_for(app_url: &str, token: &str, key: &str, route: ShareRoute) -> String {
    format!(
        "{}/{}/{token}#key={}",
        app_url.trim_end_matches('/'),
        route.as_str(),
        percent_encode(key)
    )
}

/// Parse a share link on either route and on any host (legacy hosts included).
///
/// The query string is ignored and may be present. The fragment value is
/// percent-decoded; it is not interpreted further, so both base64 alphabets
/// survive to [`key_bytes`].
pub fn parse(url: &str) -> Result<ShareLink, ShareLinkError> {
    let (scheme, rest) = url.split_once("://").ok_or(ShareLinkError::NotAShareLink)?;
    if scheme.is_empty() || scheme.contains('/') {
        return Err(ShareLinkError::NotAShareLink);
    }
    let (before_fragment, fragment) = rest.split_once('#').ok_or(ShareLinkError::MissingFragment)?;
    let before_query = before_fragment.split('?').next().unwrap_or("");

    let (authority, path) = match before_query.find('/') {
        Some(index) => (&before_query[..index], &before_query[index..]),
        None => (before_query, ""),
    };
    if authority.is_empty() {
        return Err(ShareLinkError::NotAShareLink);
    }

    let segments: Vec<&str> = path.split('/').filter(|segment| !segment.is_empty()).collect();
    if segments.len() < 2 {
        return Err(ShareLinkError::MissingToken);
    }
    let token = segments[segments.len() - 1];
    let route = ShareRoute::from_segment(segments[segments.len() - 2]).ok_or(ShareLinkError::NotAShareLink)?;

    let base_url = if segments.len() > 2 {
        format!("{scheme}://{authority}/{}", segments[..segments.len() - 2].join("/"))
    } else {
        format!("{scheme}://{authority}")
    };

    let encoded_key = fragment.strip_prefix("key=").ok_or(ShareLinkError::MissingKey)?;
    let key = percent_decode(encoded_key);
    if key.is_empty() {
        return Err(ShareLinkError::MissingKey);
    }

    Ok(ShareLink {
        base_url,
        route,
        token: token.to_string(),
        key,
    })
}

/// Decode a `#key=` value as bytes, accepting standard base64 (legacy links)
/// and base64url (current links), padded or unpadded.
///
/// This mirrors mobile's `fragmentKeyToBytes`: `-`/`_` become `+`/`/`, the
/// value is padded to a multiple of four, then decoded. `None` when the value
/// is not base64 in either alphabet.
pub fn key_bytes(key: &str) -> Option<Vec<u8>> {
    if key.is_empty() {
        return None;
    }
    let normalized: Vec<u8> = key
        .bytes()
        .map(|byte| match byte {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .collect();
    let mut padded = normalized;
    match padded.len() % 4 {
        2 => padded.extend_from_slice(b"=="),
        3 => padded.extend_from_slice(b"="),
        // A remainder of one can never be valid base64; let the decoder reject it.
        _ => {}
    }
    STANDARD.decode(padded).ok()
}

/// `encodeURIComponent`'s unreserved set.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')')
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode a fragment value. A `%` that does not introduce two hex
/// digits is kept literally, so a stray `%` never fails the parse.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                decoded.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}
