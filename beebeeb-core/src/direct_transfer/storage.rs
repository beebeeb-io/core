//! Was a storage GET answer the chunk we asked for? (task 2173, plan K1; clients design §6.4)
//!
//! The web pump already checked this in TypeScript: `storage-fetch.ts` refused anything that was not
//! a `200`, compared `Content-Length` with the grant, and required `offset === length`. The rule every
//! client applies is the same: **`Stored` means status `200` and `Content-Length` equal to the grant**,
//! never a redirect, a `206` or a shorter/longer body. Anything else is a failure that carries the
//! status (never the body and never the URL); status `0` means there was no HTTP answer at all.
//!
//! `Content-Length` is only the head. `Stored` says the response *declared* the grant's length, so the
//! caller must still count the bytes it actually reads and check them with [`check_storage_body`]: a
//! truncated stream can end short, and a proxy can lie about the length it will send.
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

impl StorageGet {
    /// Stable machine name (bindings and vectors): `"stored"` or `"failed"`.
    pub fn kind(self) -> &'static str {
        match self {
            StorageGet::Stored => "stored",
            StorageGet::Failed { .. } => "failed",
        }
    }
}

/// Check a storage GET answer: [`StorageGet::Stored`] only for `200` with `Some(expected)`.
pub fn check_storage_get(status: u16, content_length: Option<u64>, expected: u64) -> StorageGet {
    if status == 200 && content_length == Some(expected) {
        StorageGet::Stored
    } else {
        StorageGet::Failed { status }
    }
}

/// Check the body a storage GET actually delivered: [`StorageGet::Stored`] only when the received
/// count equals the grant. The status is `200` because the head already passed; a short read or an
/// overlong body is still a failed chunk.
pub fn check_storage_body(received: u64, expected: u64) -> StorageGet {
    if received == expected {
        StorageGet::Stored
    } else {
        StorageGet::Failed { status: 200 }
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

    #[test]
    fn the_counted_body_must_equal_the_grant() {
        assert_eq!(check_storage_body(CHUNK, CHUNK), StorageGet::Stored);
        assert_eq!(
            check_storage_body(CHUNK - 1, CHUNK),
            StorageGet::Failed { status: 200 },
            "a body that ended short is not the chunk"
        );
        assert_eq!(
            check_storage_body(CHUNK + 1, CHUNK),
            StorageGet::Failed { status: 200 },
            "a body longer than the grant is not the chunk, even after a 200 head"
        );
        assert_eq!(
            check_storage_body(0, 0),
            StorageGet::Stored,
            "an empty chunk is exact at zero"
        );
    }

    #[test]
    fn the_kinds_are_the_stable_names() {
        assert_eq!(StorageGet::Stored.kind(), "stored");
        assert_eq!(StorageGet::Failed { status: 0 }.kind(), "failed");
        assert_eq!(StorageGet::Failed { status: 206 }.kind(), "failed");
    }
}
