//! The pure checks every download planner applies to a window answer, in ONE place: the
//! whole-file [`super::DownloadPlanner`] and the range planner ([`super::range::RangePlanner`])
//! both call [`check_window`], so neither can drop a rule the other keeps (LD-0105, crypto
//! delta N-P2-2: a new planner type composes these checks, it never copies them).
//!
//! What is checked, in order: the transport, the file, the pin (a window for another version is
//! [`Rejected::VersionChanged`]), the geometry (a real version's numbers, and the same numbers as
//! every earlier window), the grants (exactly the window that was asked for, in order), each
//! grant's method and length, its link ([`check_storage_url`]) and its expiry (inside the skew
//! margin it is refused). Plus the two budget rules the planners share: the renewal budget (so
//! no input makes a planner loop on the API) and the 429 cap on window requests.

use chrono::DateTime;

use super::authority::{Refusal, check_storage_url};
use super::window::{Geometry, Violation};
use super::wire::{CAP_OBJECT_DOWNLOAD_V1, ChunkGrant, Discovery, DownloadGrantRequest, DownloadGrantResponse};

/// Why a planner refuses the content of a window answer: [`Violation`] without `Unexpected`, which
/// is a caller's bug (an answer nobody asked for) and never a property of an answer's content. A separate
/// type makes the compiler prove that checking an answer cannot produce it, so `window_answered` has no
/// arm for it that could quietly come to be relied on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rejected {
    Transport,
    FileMismatch,
    VersionChanged,
    Geometry,
    Grants,
    Length,
    Method,
    Authority(Refusal),
    Expiry,
}

impl From<Rejected> for Violation {
    fn from(rejected: Rejected) -> Self {
        match rejected {
            Rejected::Transport => Violation::Transport,
            Rejected::FileMismatch => Violation::FileMismatch,
            Rejected::VersionChanged => Violation::VersionChanged,
            Rejected::Geometry => Violation::Geometry,
            Rejected::Grants => Violation::Grants,
            Rejected::Length => Violation::Length,
            Rejected::Method => Violation::Method,
            Rejected::Authority(refusal) => Violation::Authority(refusal),
            Rejected::Expiry => Violation::Expiry,
        }
    }
}

/// What a planner knows when it judges a window answer.
pub(super) struct WindowCheck<'a> {
    pub file_id: &'a str,
    pub discovery: &'a Discovery,
    pub api_base: &'a str,
    /// The version this planner is pinned to, if any (the request's own pin wins).
    pub pinned: Option<&'a str>,
    /// The geometry an earlier window (or the caller) established; every answer must repeat it.
    pub known: Option<Geometry>,
    pub url_ttl_ms: i64,
    pub renew_skew_ms: i64,
}

/// A window answer that passed every check: nothing of it is committed yet.
pub(super) struct CheckedWindow {
    pub geometry: Geometry,
    pub object_version_id: String,
    /// One past the last index the window covers.
    pub end: u32,
    /// Each grant with the client-clock moment it stops being usable.
    pub grants: Vec<(ChunkGrant, i64)>,
}

/// Judge `response` as the answer to `request`. Pure: the caller commits the result.
pub(super) fn check_window(
    check: &WindowCheck<'_>,
    request: &DownloadGrantRequest,
    response: DownloadGrantResponse,
    now_ms: i64,
) -> Result<CheckedWindow, Rejected> {
    if response.transport != CAP_OBJECT_DOWNLOAD_V1 {
        return Err(Rejected::Transport);
    }
    if !response.file_id.eq_ignore_ascii_case(check.file_id) {
        return Err(Rejected::FileMismatch);
    }
    if response.object_version_id.is_empty() {
        return Err(Rejected::Geometry);
    }
    if let Some(pin) = request.object_version_id.as_deref().or(check.pinned)
        && !response.object_version_id.eq_ignore_ascii_case(pin)
    {
        return Err(Rejected::VersionChanged);
    }
    let geometry = Geometry {
        chunk_count: response.chunk_count,
        chunk_size: response.chunk_size,
        encrypted_size: response.encrypted_size,
        original_size: response.original_size,
    };
    if !geometry.is_consistent() || check.known.is_some_and(|known| known != geometry) {
        return Err(Rejected::Geometry);
    }

    let start = request.start_index;
    if start >= geometry.chunk_count {
        return Err(Rejected::Grants);
    }
    let end = (u64::from(start) + u64::from(request.count)).min(u64::from(geometry.chunk_count)) as u32;
    if response.grants.len() != (end - start) as usize {
        return Err(Rejected::Grants);
    }
    if response.next_index != (end < geometry.chunk_count).then_some(end) {
        return Err(Rejected::Grants);
    }

    let mut grants = Vec::with_capacity(response.grants.len());
    for (offset, grant) in response.grants.into_iter().enumerate() {
        if grant.index != start + offset as u32 {
            return Err(Rejected::Grants);
        }
        if grant.method != "GET" {
            return Err(Rejected::Method);
        }
        if Some(grant.length) != geometry.chunk_length(grant.index) {
            return Err(Rejected::Length);
        }
        check_storage_url(&grant.url, check.discovery, check.api_base).map_err(Rejected::Authority)?;
        let usable_until_ms = usable_until(&grant.expires_at, now_ms, check.url_ttl_ms, check.renew_skew_ms)?;
        grants.push((grant, usable_until_ms));
    }
    Ok(CheckedWindow {
        geometry,
        object_version_id: response.object_version_id,
        end,
        grants,
    })
}

/// When a grant that arrived at `now_ms` stops being usable, on the client clock.
pub(super) fn usable_until(expires_at: &str, now_ms: i64, ttl: i64, skew: i64) -> Result<i64, Rejected> {
    let expires_ms = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| Rejected::Expiry)?
        .timestamp_millis();
    let stated = expires_ms.saturating_sub(now_ms);
    // A link never lives longer than the TTL, and no server issues links
    // shorter than a minute: a stated lifetime under that is this clock
    // running ahead, so the lifetime counts from the arrival instead.
    let lifetime = if stated >= super::window::MIN_STATED_LIFETIME_MS.min(ttl) {
        stated.min(ttl)
    } else {
        ttl
    };
    let usable_until = now_ms.saturating_add(lifetime).saturating_sub(skew);
    if usable_until <= now_ms {
        return Err(Rejected::Expiry);
    }
    Ok(usable_until)
}

/// A chunk's tries so far.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Attempts {
    pub renewals: u8,
    pub auth_failures: u8,
}

impl Attempts {
    /// Spend one renewal; `true` when the budget is used up and the chunk must go to the pinned API
    /// route. The one renewal rule both planners apply (`window.rs` module docs).
    pub fn spend_renewal(&mut self, max_renewals: u8) -> bool {
        self.renewals = self.renewals.saturating_add(1);
        self.renewals > max_renewals
    }
}

/// Count one 429 on a window request; `true` when the cap is passed and the file's windows are
/// unusable. The one 429 rule both planners apply.
pub(super) fn rate_limit_spent(rate_limits: &mut u8, max_rate_limits: u8) -> bool {
    *rate_limits = rate_limits.saturating_add(1);
    *rate_limits > max_rate_limits
}

/// The renewal backoff of attempt `attempt` (1-based): `base * 2^(attempt-1)`, capped, with equal
/// jitter. The one formula both planners apply.
pub(super) fn backoff_delay(rng: &mut u64, base_ms: u64, cap_ms: u64, attempt: u8) -> i64 {
    let shift = u32::from(attempt.saturating_sub(1)).min(20);
    let exp = base_ms.saturating_mul(1u64 << shift).min(cap_ms);
    i64::try_from(super::window::equal_jitter(rng, exp)).unwrap_or(i64::MAX)
}
