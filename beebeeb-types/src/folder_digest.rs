//! Wire types of `GET /api/v1/folder-digests` (folder digest v1; the
//! definition is `beebeeb_core::folder_digest` and `docs/folder-digest.md`).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One page of a folder's children with their digests.
///
/// Every page carries the folder's digest and child count at that page's read;
/// a client that sees `digest` change between pages starts the folder again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FolderDigestPage {
    /// The folder; None = the caller's root.
    pub folder_id: Option<Uuid>,
    /// `bb-folder-digest-v1`.
    pub algorithm: String,
    /// The folder's digest, 64 lowercase hex.
    pub digest: String,
    /// Number of children in the folder's child set.
    pub child_count: i64,
    /// Children ordered by id ascending (empty for `limit=0`).
    pub children: Vec<FolderDigestChild>,
    /// Opaque keyset cursor of the next page; None on the last page.
    pub next_cursor: Option<String>,
}

/// One child in a [`FolderDigestPage`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FolderDigestChild {
    pub id: Uuid,
    pub is_folder: bool,
    /// Folders only: that folder's digest, 64 lowercase hex.
    pub digest: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "folder_id": "f01de000-0000-4000-8000-000000000310",
        "algorithm": "bb-folder-digest-v1",
        "digest": "db890c62967d99016e43cbf649ab13075e3d1b6b94d791b9071ed95be0a58795",
        "child_count": 2,
        "children": [
            {"id": "f01de000-0000-4000-8000-000000000311", "is_folder": false, "digest": null},
            {"id": "f01de000-0000-4000-8000-000000000320", "is_folder": true,
             "digest": "db890c62967d99016e43cbf649ab13075e3d1b6b94d791b9071ed95be0a58795"}
        ],
        "next_cursor": null
    }"#;

    #[test]
    fn folder_digest_page_round_trips_the_sample() {
        let page: FolderDigestPage = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(
            page.folder_id,
            Some(Uuid::parse_str("f01de000-0000-4000-8000-000000000310").unwrap())
        );
        assert_eq!(page.child_count, 2);
        assert!(page.children[1].is_folder);
        assert_eq!(page.children[0].digest, None);
        assert_eq!(page.next_cursor, None);
        let back: serde_json::Value = serde_json::to_value(&page).unwrap();
        let want: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(back, want);
        assert_eq!(serde_json::from_value::<FolderDigestPage>(back).unwrap(), page);
    }

    #[test]
    fn folder_digest_root_page_has_a_null_folder_id() {
        let page = FolderDigestPage {
            folder_id: None,
            algorithm: "bb-folder-digest-v1".into(),
            digest: "00".repeat(32),
            child_count: 0,
            children: Vec::new(),
            next_cursor: Some("c1".into()),
        };
        let v = serde_json::to_value(&page).unwrap();
        assert!(v["folder_id"].is_null());
        assert_eq!(v["next_cursor"], "c1");
        assert_eq!(serde_json::from_value::<FolderDigestPage>(v).unwrap(), page);
    }
}
