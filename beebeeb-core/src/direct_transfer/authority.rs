//! Which storage links a client may follow, and how a link is shown.
//!
//! [`check_storage_url`] is the client-side authority check of the direct S3
//! contract (R1.12): a grant URL is followed only if it names a `{host,
//! bucket}` pair the server listed in discovery, over https, without
//! credentials, on a port the server listed. It is defence in depth: the list
//! comes from the same API that signs the links, so the real protection is that
//! chunks are decrypted with keys the API never has.
//!
//! # Why a strict grammar instead of a URL parser
//!
//! The check has to agree with whatever HTTP stack then connects (reqwest's
//! `url`, Foundation's `URL`, the browser's WHATWG parser). Those parsers
//! disagree on exactly the inputs an attacker picks: `\` is a `/` to WHATWG,
//! tabs and newlines are silently dropped, `0x7f.1` is `127.0.0.1`,
//! `/b/../evil/x` is `/evil/x`. So this parser accepts only the shape a real
//! presigned path-style URL has and **refuses everything it would have to
//! interpret**: printable ASCII only, no `\`, `#`, `%` or `@` in the authority,
//! no dot segments, no empty segments, no IP-looking hosts. A URL inside that
//! grammar means the same thing to every parser, so what was checked is what
//! gets fetched. The tests also run every accepted URL through the `url` crate
//! and require the same host, port and path prefix.
//!
//! [`redact`] and [`scrub`] are the only ways a URL (or text that may contain
//! one) is allowed into a log line, error message or progress event. They keep
//! the scheme and host only: the path names the tenant, the version and the key.

/// Longest URL accepted. Real presigned URLs are about 1 KiB.
pub const MAX_URL_LEN: usize = 8 * 1024;

/// Why a storage link was refused. The text never contains the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the storage link is not a plain printable-ASCII URL")]
    Malformed,
    #[error("the storage link does not use https")]
    NotHttps,
    #[error("the storage link carries credentials")]
    Userinfo,
    #[error("the storage link names an IP address")]
    IpLiteral,
    #[error("the storage link names this machine (loopback), which is allowed only in local development")]
    Loopback,
    #[error("the storage link names a host in an unexpected form")]
    BadHost,
    #[error("the storage link names a non-default port")]
    Port,
    #[error("the storage link names a host the server did not list")]
    HostNotListed,
    #[error("the storage link does not address a bucket the server listed")]
    BucketNotListed,
    #[error("the storage link path is not a plain object path")]
    BadPath,
}

/// A URL taken apart by the strict grammar.
struct Parsed<'a> {
    https: bool,
    /// Lowercased host, validated.
    host: String,
    /// Explicit port, with the scheme's default port dropped.
    port: Option<u16>,
    /// Everything from the first `/` or `?` after the authority (may be empty).
    rest: &'a str,
}

impl Parsed<'_> {
    fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host == "localhost"
}

/// Strip an ASCII-case-insensitive prefix.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// The last label of a host looks like a number to a WHATWG parser (`1`,
/// `0x7f`): such a host is an IPv4 address in disguise.
fn ends_in_a_number(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or("");
    if last.is_empty() {
        return false;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    last.strip_prefix("0x")
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn parse(url: &str) -> Result<Parsed<'_>, Refusal> {
    if url.is_empty() || url.len() > MAX_URL_LEN {
        return Err(Refusal::Malformed);
    }
    // One byte class for the whole URL: visible ASCII. This removes control
    // characters (which WHATWG strips silently), whitespace (which it trims),
    // and every non-ASCII lookalike in one rule.
    if !url.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(Refusal::Malformed);
    }
    // `\` is `/` to WHATWG; `#` starts a fragment that is never sent.
    if url.contains('\\') || url.contains('#') {
        return Err(Refusal::Malformed);
    }
    let (https, after) = if let Some(rest) = strip_prefix_ci(url, "https://") {
        (true, rest)
    } else if let Some(rest) = strip_prefix_ci(url, "http://") {
        (false, rest)
    } else {
        return Err(Refusal::NotHttps);
    };
    let auth_end = after.find(['/', '?']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(auth_end);
    if authority.is_empty() {
        return Err(Refusal::BadHost);
    }
    if authority.contains('@') {
        return Err(Refusal::Userinfo);
    }
    if authority.contains('[') || authority.contains(']') {
        return Err(Refusal::IpLiteral);
    }
    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or("");
    let port_text = parts.next();
    if parts.next().is_some() {
        // More than one colon: an unbracketed IPv6 literal or garbage.
        return Err(Refusal::BadHost);
    }
    let host = host.to_ascii_lowercase();
    if !valid_dns_name(&host) {
        return Err(Refusal::BadHost);
    }
    let default_port = if https { 443 } else { 80 };
    let port = match port_text {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Refusal::BadHost);
            }
            let n: u32 = p.parse().map_err(|_| Refusal::BadHost)?;
            if n == 0 || n > u32::from(u16::MAX) {
                return Err(Refusal::BadHost);
            }
            (n != default_port).then_some(n as u16)
        }
    };
    Ok(Parsed {
        https,
        host,
        port,
        rest,
    })
}

/// A path segment that a normalizing parser would collapse (`.`, `..`, or
/// their percent-encoded forms).
fn is_dot_segment(segment: &str) -> bool {
    let lowered = segment.to_ascii_lowercase().replace("%2e", ".");
    lowered == "." || lowered == ".."
}

/// May a client follow `url` for a chunk transfer?
///
/// `api_base` is the API origin the client talks to; it decides whether the
/// loopback-development exceptions apply (`http://127.0.0.1` or
/// `http://localhost` only).
pub fn check_storage_url(url: &str, discovery: &super::Discovery, api_base: &str) -> Result<(), Refusal> {
    let parsed = parse(url)?;
    let dev = parse(api_base)
        .map(|api| !api.https && is_loopback_host(&api.host))
        .unwrap_or(false);
    let loopback = is_loopback_host(&parsed.host);
    // The loopback exceptions (plain http, a non-default port, the address
    // itself) are one switch: the API itself is on loopback http. The loopback
    // NAME and ADDRESS are treated alike.
    let dev_loopback = dev && loopback;

    if !parsed.https && !dev_loopback {
        return Err(Refusal::NotHttps);
    }
    if loopback && !dev {
        return Err(Refusal::Loopback);
    }
    if ends_in_a_number(&parsed.host) && !dev_loopback {
        return Err(Refusal::IpLiteral);
    }
    // R1.12: a non-default port is refused outright, even when discovery lists
    // it; the server's own list is not independent approval.
    if parsed.port.is_some() && !dev_loopback {
        return Err(Refusal::Port);
    }

    let authority = parsed.authority();
    if !discovery
        .storage_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&authority))
    {
        return Err(Refusal::HostNotListed);
    }

    // Path-style addressing: `/<bucket>/<key…>` with the bucket listed for
    // THIS host. One host serves every bucket, so the host alone is not enough.
    let path = match parsed.rest.split_once('?') {
        Some((path, _query)) => path,
        None => parsed.rest,
    };
    let Some(path) = path.strip_prefix('/') else {
        return Err(Refusal::BucketNotListed);
    };
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 2 {
        return Err(Refusal::BucketNotListed);
    }
    if segments.iter().any(|s| s.is_empty() || is_dot_segment(s)) {
        return Err(Refusal::BadPath);
    }
    let bucket = segments[0];
    let bucket_listed = discovery
        .storage_buckets
        .iter()
        .any(|b| b.host.eq_ignore_ascii_case(&authority) && b.bucket == bucket);
    if !bucket_listed {
        return Err(Refusal::BucketNotListed);
    }
    Ok(())
}

/// A URL for a log line or error: scheme and host only. The query and fragment
/// (they carry the signature), credentials, and the PATH (bucket, tenant and
/// version ids, the object key) are all replaced; length bounded.
pub fn redact(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    let head = &url[..cut];
    let mut out = match head.find("://") {
        Some(p) => {
            let (scheme, rest) = head.split_at(p + 3);
            let auth_end = rest.find('/').unwrap_or(rest.len());
            let (authority, tail) = rest.split_at(auth_end);
            let authority = authority.rsplit('@').next().unwrap_or(authority);
            if tail.is_empty() || tail == "/" {
                format!("{scheme}{authority}{tail}")
            } else {
                format!("{scheme}{authority}/<redacted>")
            }
        }
        None => head.to_string(),
    };
    const MAX: usize = 256;
    if out.chars().count() > MAX {
        out = out.chars().take(MAX).collect::<String>() + "…";
    }
    out
}

/// Characters that end a URL token inside prose (`error sending request for
/// url (https://…)`).
fn ends_url(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
}

/// Make text that MAY contain URLs safe to print: every `http(s)://` token is
/// replaced by its [`redact`]ed form, and any leftover `X-Amz-…` parameter is
/// masked. Use it on error strings that come from an HTTP stack.
pub fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let lower = rest.to_ascii_lowercase();
        let found = [lower.find("https://"), lower.find("http://")]
            .into_iter()
            .flatten()
            .min();
        let Some(start) = found else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.find(ends_url).unwrap_or(tail.len());
        out.push_str(&redact(&tail[..end]));
        rest = &tail[end..];
    }
    mask_amz_params(&out)
}

fn mask_amz_params(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(rel) = lower[at..].find("x-amz-") {
        let start = at + rel;
        out.push_str(&text[at..start]);
        out.push_str("x-amz-[redacted]");
        let stop = text[start..]
            .find(|c: char| c == '&' || ends_url(c))
            .map_or(text.len(), |i| start + i);
        at = stop;
    }
    out.push_str(&text[at..]);
    out
}
