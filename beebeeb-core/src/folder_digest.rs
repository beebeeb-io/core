//! Folder digest v1: one 32-byte value per folder that changes when anything a
//! listing shows about the folder's subtree changes (spec: `docs/folder-digest.md`,
//! vectors: `test-vectors/folder_digest_v1.json`).
//!
//! The server keeps a digest per folder and one per account root; a client
//! compares the digest it holds with the server's and walks down only where they
//! differ. Every client and the server compute it with this module, so the
//! bytes here are a wire format: **v1 never changes**. A change is a v2 with new
//! derive-key contexts and a new [`ALGORITHM`] string.
//!
//! A digest covers server-side metadata only (ids, sizes, versions, object
//! version ids, a hash of the name *ciphertext*, child folder digests). It never
//! sees a plaintext name or a key. Pure code, no I/O.

use uuid::Uuid;

/// The algorithm name the server sends with every digest.
pub const ALGORITHM: &str = "bb-folder-digest-v1";

/// BLAKE3 `derive_key` context of a folder digest.
pub const DIGEST_CONTEXT: &str = "beebeeb folder digest v1";

/// BLAKE3 `derive_key` context of a child's name hash.
pub const NAME_HASH_CONTEXT: &str = "beebeeb folder digest v1 name";

/// Length of one encoded child record.
pub const RECORD_LEN: usize = 114;

/// A folder digest.
pub type Digest = [u8; 32];

/// The digest of a folder with no children: `folder_digest(vec![])`. A folder
/// the server has no digest row for has this digest.
pub const EMPTY: Digest = [
    0xdb, 0x89, 0x0c, 0x62, 0x96, 0x7d, 0x99, 0x01, 0x6e, 0x43, 0xcb, 0xf6, 0x49, 0xab, 0x13, 0x07, 0x5e, 0x3d, 0x1b,
    0x6b, 0x94, 0xd7, 0x91, 0xb9, 0x07, 0x1e, 0xd9, 0x5b, 0xe0, 0xa5, 0x87, 0x95,
];

/// Whether a child is a file or a folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChildKind {
    File,
    Folder,
}

/// One child of a folder, as it enters the digest.
///
/// A file: the server's row as it is, also while `uploading` (a new version's
/// init already changes size and version); `folder_digest` None.
/// A folder: `uploading` false, size 0, version 0, object version None,
/// `folder_digest` Some(that folder's digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildRecord {
    pub id: Uuid,
    pub kind: ChildKind,
    pub uploading: bool,
    pub size_bytes: i64,
    pub version_number: i64,
    pub object_version_id: Option<Uuid>,
    pub name_hash: [u8; 32],
    pub folder_digest: Option<Digest>,
}

/// BLAKE3 `derive_key(NAME_HASH_CONTEXT)` over the UTF-8 bytes of the name
/// ciphertext string exactly as the server stores it and sends it in JSON. It is
/// never decoded first: every client holds that same string, whatever its inner
/// encoding.
pub fn name_hash(name_encrypted: &str) -> [u8; 32] {
    blake3::derive_key(NAME_HASH_CONTEXT, name_encrypted.as_bytes())
}

/// The 114-byte record: kind u8 (1 file, 2 folder) | flags u8 (bit 0 =
/// uploading) | id 16 | size_bytes i64 BE | version_number i64 BE |
/// object_version_id 16 (zeros when None) | name_hash 32 | folder_digest 32
/// (zeros when None).
pub fn encode_record(r: &ChildRecord) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    out[0] = match r.kind {
        ChildKind::File => 1,
        ChildKind::Folder => 2,
    };
    out[1] = u8::from(r.uploading);
    out[2..18].copy_from_slice(r.id.as_bytes());
    out[18..26].copy_from_slice(&r.size_bytes.to_be_bytes());
    out[26..34].copy_from_slice(&r.version_number.to_be_bytes());
    if let Some(ov) = r.object_version_id {
        out[34..50].copy_from_slice(ov.as_bytes());
    }
    out[50..82].copy_from_slice(&r.name_hash);
    if let Some(d) = r.folder_digest {
        out[82..114].copy_from_slice(&d);
    }
    out
}

/// BLAKE3 `derive_key(DIGEST_CONTEXT)` over `u64 BE child count` followed by
/// `encode_record` of every child, sorted by id bytes ascending. The order the
/// children are given in does not matter.
pub fn folder_digest(mut children: Vec<ChildRecord>) -> Digest {
    children.sort_unstable_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
    let mut h = blake3::Hasher::new_derive_key(DIGEST_CONTEXT);
    h.update(&(children.len() as u64).to_be_bytes());
    for c in &children {
        h.update(&encode_record(c));
    }
    *h.finalize().as_bytes()
}

/// 64 lowercase hex characters.
pub fn to_hex(d: &Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0x0f)] as char);
    }
    s
}

/// The inverse of [`to_hex`]: exactly 64 lowercase hex characters, else None.
pub fn from_hex(s: &str) -> Option<Digest> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;

    const VECTORS: &str = include_str!("../../test-vectors/folder_digest_v1.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vector file parses")
    }

    fn hex32(v: &Value) -> [u8; 32] {
        from_hex(v.as_str().expect("hex string")).expect("64 lowercase hex")
    }

    fn uuid(v: &Value) -> Uuid {
        Uuid::parse_str(v.as_str().expect("uuid string")).expect("uuid")
    }

    fn child(v: &Value) -> ChildRecord {
        ChildRecord {
            id: uuid(&v["id"]),
            kind: match v["kind"].as_str() {
                Some("file") => ChildKind::File,
                Some("folder") => ChildKind::Folder,
                other => panic!("bad kind {other:?}"),
            },
            uploading: v["uploading"].as_bool().unwrap(),
            size_bytes: v["size_bytes"].as_i64().unwrap(),
            version_number: v["version_number"].as_i64().unwrap(),
            object_version_id: (!v["object_version_id"].is_null()).then(|| uuid(&v["object_version_id"])),
            name_hash: name_hash(v["name_encrypted"].as_str().unwrap()),
            folder_digest: (!v["folder_digest"].is_null()).then(|| hex32(&v["folder_digest"])),
        }
    }

    fn children(v: &Value) -> Vec<ChildRecord> {
        v.as_array().unwrap().iter().map(child).collect()
    }

    #[test]
    fn folder_digest_header_matches_the_vector_file() {
        let v = vectors();
        assert_eq!(v["algorithm"], ALGORITHM);
        assert_eq!(v["digest_context"], DIGEST_CONTEXT);
        assert_eq!(v["name_context"], NAME_HASH_CONTEXT);
        assert_eq!(hex32(&v["empty"]), EMPTY);
        assert_eq!(folder_digest(Vec::new()), EMPTY);
    }

    #[test]
    fn folder_digest_name_hashes_match() {
        for case in vectors()["name_hashes"].as_array().unwrap() {
            let name = case["name_encrypted"].as_str().unwrap();
            assert_eq!(to_hex(&name_hash(name)), case["name_hash"].as_str().unwrap(), "{name}");
        }
    }

    #[test]
    fn folder_digest_records_encode_as_the_vectors() {
        for case in vectors()["records"].as_array().unwrap() {
            let r = child(&case["child"]);
            let enc = encode_record(&r);
            assert_eq!(hex::encode(enc), case["encoded"].as_str().unwrap(), "{:?}", r.id);
        }
    }

    #[test]
    fn folder_digest_folders_match_and_equal_and_distinct_groups_hold() {
        let v = vectors();
        let mut by_name = HashMap::new();
        for case in v["folders"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let got = folder_digest(children(&case["children"]));
            assert_eq!(to_hex(&got), case["digest"].as_str().unwrap(), "folder vector {name}");
            by_name.insert(name.to_string(), got);
        }
        for group in v["equal"].as_array().unwrap() {
            let ds: Vec<_> = group
                .as_array()
                .unwrap()
                .iter()
                .map(|n| by_name[n.as_str().unwrap()])
                .collect();
            assert!(ds.windows(2).all(|w| w[0] == w[1]), "{group}");
        }
        for group in v["distinct"].as_array().unwrap() {
            let names: Vec<_> = group.as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
            for (i, a) in names.iter().enumerate() {
                for b in &names[i + 1..] {
                    assert_ne!(by_name[*a], by_name[*b], "{a} and {b} must differ");
                }
            }
        }
    }

    /// Computes a vector tree bottom-up and records every folder's digest
    /// (`"root"` for the account root).
    fn walk(node: &Value, out: &mut HashMap<String, Digest>) -> Digest {
        let mut kids = Vec::new();
        for c in node["children"].as_array().unwrap() {
            if c["kind"] == "folder" {
                let d = walk(c, out);
                kids.push(ChildRecord {
                    id: uuid(&c["id"]),
                    kind: ChildKind::Folder,
                    uploading: false,
                    size_bytes: 0,
                    version_number: 0,
                    object_version_id: None,
                    name_hash: name_hash(c["name_encrypted"].as_str().unwrap()),
                    folder_digest: Some(d),
                });
            } else {
                kids.push(child(c));
            }
        }
        let d = folder_digest(kids);
        let key = node["id"].as_str().unwrap_or("root").to_string();
        out.insert(key, d);
        d
    }

    #[test]
    fn folder_digest_trees_match() {
        for tree in vectors()["trees"].as_array().unwrap() {
            let mut got = HashMap::new();
            let root = walk(&tree["root"], &mut got);
            assert_eq!(to_hex(&root), tree["root_digest"].as_str().unwrap());
            let want = tree["folder_digests"].as_object().unwrap();
            assert_eq!(got.len(), want.len());
            for (id, hex) in want {
                assert_eq!(to_hex(&got[id]), hex.as_str().unwrap(), "folder {id}");
            }
        }
    }

    #[test]
    fn folder_digest_hex_round_trips_and_is_strict() {
        let d = folder_digest(Vec::new());
        assert_eq!(from_hex(&to_hex(&d)), Some(d));
        assert_eq!(to_hex(&[0xab; 32]), "ab".repeat(32));
        assert_eq!(from_hex(&"AB".repeat(32)), None);
        assert_eq!(from_hex(&"ab".repeat(31)), None);
        assert_eq!(from_hex(&"ab".repeat(33)), None);
        assert_eq!(from_hex(&format!("{}g0", "ab".repeat(31))), None);
        assert_eq!(from_hex(""), None);
    }

    #[test]
    fn folder_digest_contexts_are_separate_from_each_other() {
        // The same bytes under the two contexts never give the same key.
        let input = [0u8; 8];
        assert_ne!(
            blake3::derive_key(DIGEST_CONTEXT, &input),
            blake3::derive_key(NAME_HASH_CONTEXT, &input)
        );
    }
}
