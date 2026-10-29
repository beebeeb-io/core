//! Was a storage GET answer the chunk we asked for? (task 2173, plan K1; clients design §6.4)
//!
//! The web pump decided this in TypeScript (`status === 200`), so a short body, a redirect or a
//! `206` could pass. This is the rule every client applies: a storage GET delivered the chunk only
//! when it answered `200` **and** `Content-Length` was exactly the grant's length. Anything else is
//! a failure that carries the status (never the body and never the URL); status `0` means there was
//! no HTTP answer at all.
//!
//! Pure data: no I/O, no clock.

/// What a storage GET answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageGet {
    /// `200` and exactly the expected number of bytes.
    Stored,
    /// Anything else. `0` means there was no HTTP answer at all.
    Failed { status: u16 },
}

/// Check a storage GET answer: [`StorageGet::Stored`] only for `200` with `Some(expected)`.
pub fn check_storage_get(status: u16, content_length: Option<u64>, expected: u64) -> StorageGet {
    if status == 200 && content_length == Some(expected) {
        StorageGet::Stored
    } else {
        StorageGet::Failed { status }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHUNK: u64 = 4 * 1024 * 1024 + 28;

    #[test]
    fn only_200_with_the_exact_length_is_a_stored_chunk() {
        assert_eq!(check_storage_get(200, Some(CHUNK), CHUNK), StorageGet::Stored);
        assert_eq!(
            check_storage_get(200, Some(CHUNK - 1), CHUNK),
            StorageGet::Failed { status: 200 },
            "a short body is not the chunk"
        );
        assert_eq!(
            check_storage_get(200, Some(CHUNK + 1), CHUNK),
            StorageGet::Failed { status: 200 },
            "a body longer than the grant is not the chunk"
        );
        assert_eq!(
            check_storage_get(200, None, CHUNK),
            StorageGet::Failed { status: 200 },
            "no Content-Length is not the chunk"
        );
        assert_eq!(
            check_storage_get(206, Some(CHUNK), CHUNK),
            StorageGet::Failed { status: 206 },
            "a partial answer is not the chunk"
        );
        assert_eq!(
            check_storage_get(403, Some(CHUNK), CHUNK),
            StorageGet::Failed { status: 403 }
        );
        assert_eq!(
            check_storage_get(0, None, CHUNK),
            StorageGet::Failed { status: 0 },
            "no answer at all keeps status 0"
        );
    }
}
