//! Memory classes and the storage-allowlist rule (task 2173, plan K1; clients design §6.4, §6.7).
//!
//! Two decisions the web made in TypeScript move here so every client applies them the same way:
//!
//! * **How much ciphertext may be held at once**, by process class: a native app may hold 256 MiB,
//!   a browser or a mobile app 64 MiB, a mobile extension 16 MiB. The planner clamps its chunk count
//!   to at least one (`window.rs`), so this bounds how many chunks it holds; it does not make a chunk
//!   smaller. A 256 MiB chunk is held even under a 16 MiB class. The direct path's driver (L2/K2)
//!   always sets the cap.
//! * **Whether the pairs discovery names are all one the client may talk to.** The web keeps a
//!   storage allowlist (CSP) and used to compare it itself. A direction is allowed only when the
//!   server offers it, discovery lists at least one `{host, bucket}`, and every one it names is in
//!   the allowlist. An empty list is not vacuous: `check_storage_url` refuses every bucket, so there
//!   is no storage route to use. Hosts compare ASCII case-insensitively (DNS names are
//!   case-insensitive); buckets compare exactly (S3 bucket names are case-sensitive and lower-case
//!   only).
//!
//! Pure data: no I/O, no clock.

use super::{Direction, Discovery, StorageBucket};

/// The process class, which sets the ciphertext-in-flight cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryClass {
    /// CLI, desktop: 256 MiB.
    Native,
    /// A browser tab: 64 MiB.
    Browser,
    /// A mobile app process: 64 MiB.
    MobileApp,
    /// An iOS or Android extension: 16 MiB.
    MobileExtension,
}

impl MemoryClass {
    /// Stable machine name (bindings and vectors).
    pub fn code(self) -> &'static str {
        match self {
            MemoryClass::Native => "native",
            MemoryClass::Browser => "browser",
            MemoryClass::MobileApp => "mobile_app",
            MemoryClass::MobileExtension => "mobile_extension",
        }
    }

    /// The inverse of [`MemoryClass::code`]; anything else is `None`.
    pub fn from_code(code: &str) -> Option<MemoryClass> {
        match code {
            "native" => Some(MemoryClass::Native),
            "browser" => Some(MemoryClass::Browser),
            "mobile_app" => Some(MemoryClass::MobileApp),
            "mobile_extension" => Some(MemoryClass::MobileExtension),
            _ => None,
        }
    }
}

const MIB: u64 = 1024 * 1024;

/// The ciphertext bytes a process of class `c` may hold at once. The planner clamps its chunk count
/// to at least one, so this is a ceiling on how many chunks are held, never a promise that one chunk
/// fits: a 256 MiB chunk is held even under a 16 MiB class. The L2 driver always sets the cap.
pub const fn max_in_flight_bytes(c: MemoryClass) -> u64 {
    match c {
        MemoryClass::Native => 256 * MIB,
        MemoryClass::Browser => 64 * MIB,
        MemoryClass::MobileApp => 64 * MIB,
        MemoryClass::MobileExtension => 16 * MIB,
    }
}

/// Is `pair` in `allowlist`? Host case-insensitively, bucket exactly.
fn pair_listed(pair: &StorageBucket, allowlist: &[StorageBucket]) -> bool {
    allowlist
        .iter()
        .any(|a| a.host.eq_ignore_ascii_case(&pair.host) && a.bucket == pair.bucket)
}

/// May this client use the direct transport for `direction`? Only when discovery offers it, names at
/// least one `{host, bucket}` pair, AND every pair it names is in `allowlist`. An empty list is not
/// allowed vacuously: `check_storage_url` refuses any unlisted bucket, so no storage route is left.
pub fn pairs_allowed(discovery: &Discovery, direction: Direction, allowlist: &[StorageBucket]) -> bool {
    let offered = match direction {
        Direction::Download => discovery.offers_download(),
        Direction::Upload => discovery.offers_upload(),
    };
    offered
        && !discovery.storage_buckets.is_empty()
        && discovery.storage_buckets.iter().all(|p| pair_listed(p, allowlist))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_transfer::{CAP_OBJECT_DOWNLOAD_V1, CAP_OBJECT_UPLOAD_V1};

    fn bucket(host: &str, bucket: &str) -> StorageBucket {
        StorageBucket {
            host: host.to_string(),
            bucket: bucket.to_string(),
        }
    }

    fn three() -> Discovery {
        Discovery {
            download: vec![CAP_OBJECT_DOWNLOAD_V1.to_string()],
            upload: vec![CAP_OBJECT_UPLOAD_V1.to_string()],
            storage_buckets: vec![
                bucket("s3.storage.test", "bb-01"),
                bucket("s3.storage.test", "bb-02"),
                bucket("eu.storage.test", "vault"),
            ],
            ..Discovery::default()
        }
    }

    #[test]
    fn every_discovery_pair_must_be_allowlisted() {
        let d = three();
        let two = vec![bucket("s3.storage.test", "bb-01"), bucket("s3.storage.test", "bb-02")];
        assert!(
            !pairs_allowed(&d, Direction::Download, &two),
            "one pair is missing: the direct transport is not allowed"
        );
        assert!(
            !pairs_allowed(&d, Direction::Upload, &two),
            "the upload direction agrees about the missing pair"
        );
        let all = vec![
            bucket("s3.storage.test", "bb-01"),
            bucket("s3.storage.test", "bb-02"),
            bucket("eu.storage.test", "vault"),
        ];
        assert!(pairs_allowed(&d, Direction::Download, &all));
    }

    #[test]
    fn a_direction_not_offered_is_never_allowed() {
        let d = three();
        let all = vec![
            bucket("s3.storage.test", "bb-01"),
            bucket("s3.storage.test", "bb-02"),
            bucket("eu.storage.test", "vault"),
        ];
        // The server lists no upload token.
        let download_only = Discovery {
            upload: Vec::new(),
            ..d.clone()
        };
        assert!(pairs_allowed(&download_only, Direction::Download, &all));
        assert!(!pairs_allowed(&download_only, Direction::Upload, &all));
        // The server lists no download token.
        let upload_only = Discovery {
            download: Vec::new(),
            ..d
        };
        assert!(!pairs_allowed(&upload_only, Direction::Download, &all));
        assert!(pairs_allowed(&upload_only, Direction::Upload, &all));
    }

    #[test]
    fn an_empty_bucket_list_is_not_allowed_vacuously() {
        let empty = Discovery {
            storage_buckets: Vec::new(),
            ..three()
        };
        assert!(
            !pairs_allowed(&empty, Direction::Download, &[]),
            "no listed pair means check_storage_url refuses every bucket: direct is off"
        );
        assert!(
            !pairs_allowed(&empty, Direction::Upload, &[]),
            "the upload direction agrees"
        );
        assert!(
            !pairs_allowed(&empty, Direction::Download, &[bucket("s3.storage.test", "bb-01")]),
            "an allowlist cannot make up for a discovery that names no pair"
        );
    }

    #[test]
    fn memory_classes_have_the_documented_caps() {
        assert_eq!(max_in_flight_bytes(MemoryClass::Native), 256 * MIB);
        assert_eq!(max_in_flight_bytes(MemoryClass::Browser), 64 * MIB);
        assert_eq!(max_in_flight_bytes(MemoryClass::MobileApp), 64 * MIB);
        assert_eq!(max_in_flight_bytes(MemoryClass::MobileExtension), 16 * MIB);

        // A 256 MiB chunk in a 16 MiB extension admits exactly one chunk: the planner's clamp holds it
        // even though it is far above the class's ceiling.
        let chunk = 256 * MIB + 28;
        let held = (max_in_flight_bytes(MemoryClass::MobileExtension) / chunk).clamp(1, 4);
        assert_eq!(held, 1, "the clamp keeps one chunk, it does not shrink the chunk");
    }
}
