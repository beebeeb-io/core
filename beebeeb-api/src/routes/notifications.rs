//! The filtered notification listing (server LD-0141): every row of the given
//! types written at or after a time on the server's clock, newest first, in
//! pages of at most [`FILTERED_PAGE_MAX`] rows. A page cut at its size carries
//! a `next_cursor` to pass back with the same filter; a null one ends the
//! listing. A server without the filter ignores `type`, `since` and `cursor`
//! and answers without the key at all, so [`FilteredPage::next_cursor`] tells
//! "complete" (`Some(None)`) from "not filtered" (`None`).

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::{Endpoint, Method, request::component};

/// The most rows one filtered page returns.
pub const FILTERED_PAGE_MAX: u16 = 500;

/// One `notifications` row as the filtered listing returns it.
#[derive(Debug, Clone, Deserialize)]
pub struct Notification {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub data: Option<Value>,
    /// RFC 3339, on the server's clock.
    pub created_at: String,
}

/// One page of the filtered listing.
#[derive(Debug, Clone, Deserialize)]
pub struct FilteredPage {
    #[serde(default)]
    pub notifications: Vec<Notification>,
    /// `None`: the answer had no `next_cursor` key, so the server did not
    /// filter (an older server). `Some(None)`: the listing is complete.
    /// `Some(Some(cursor))`: pass `cursor` back for the next page.
    #[serde(default, deserialize_with = "present")]
    pub next_cursor: Option<Option<String>>,
}

fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

/// `GET /api/v1/notifications?type=<types>&since=<ms>&limit=500[&cursor=<c>]`:
/// the rows of `types` written at or after `since_ms` (milliseconds since the
/// epoch, server clock). `types` are sent comma-separated.
pub fn filtered(types: &[&str], since_ms: i64, cursor: Option<&str>) -> Endpoint<(), FilteredPage> {
    let types = types.iter().map(|kind| component(kind)).collect::<Vec<_>>().join(",");
    let mut path = format!("/api/v1/notifications?type={types}&since={since_ms}&limit={FILTERED_PAGE_MAX}");
    if let Some(cursor) = cursor {
        path.push_str("&cursor=");
        path.push_str(&component(cursor));
    }
    Endpoint::new(Method::Get, path, false).limits(0, 4 * 1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_names_the_types_the_time_and_the_cursor() {
        assert_eq!(
            filtered(&["files_removed", "backup_deleted"], 1_700_000_000_123, None).path(),
            "/api/v1/notifications?type=files_removed,backup_deleted&since=1700000000123&limit=500"
        );
        assert_eq!(
            filtered(&["files_removed"], 0, Some("a+b/c")).path(),
            "/api/v1/notifications?type=files_removed&since=0&limit=500&cursor=a%2Bb%2Fc"
        );
    }

    #[test]
    fn a_missing_cursor_key_is_not_a_complete_listing() {
        let unfiltered: FilteredPage = serde_json::from_str(r#"{"notifications":[]}"#).unwrap();
        let complete: FilteredPage = serde_json::from_str(r#"{"notifications":[],"next_cursor":null}"#).unwrap();
        let more: FilteredPage = serde_json::from_str(r#"{"notifications":[],"next_cursor":"c"}"#).unwrap();
        assert_eq!(unfiltered.next_cursor, None);
        assert_eq!(complete.next_cursor, Some(None));
        assert_eq!(more.next_cursor, Some(Some("c".into())));
    }
}
