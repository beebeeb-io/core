//! Was a storage GET answer the chunk we asked for? (task 2173, plan K1; clients design §6.4)
//!
//! The web pump checked this in TypeScript on `fs/l13-s3-web-download` (unmerged): `storage-fetch.ts`
//! refused anything that was not a `200`, compared `Content-Length` with the grant, and required
//! `offset === length`. That branch reports status `0` where core carries the real status of a
//! non-200 answer. The rule every client applies is the same: **`Stored` means status `200` and
//! `Content-Length` equal to the grant**, never a redirect, a `206` or a shorter/longer body.
//! Anything else is a failure that carries the status (never the body and never the URL); status `0`
//! means there was no HTTP answer at all.
//!
//! `Content-Length` is only the head. `Stored` says the response *declared* the grant's length, so the
//! caller must still count the bytes it actually reads: [`StorageBody`] holds that count for one
//! response (head, pushes, finish); [`check_storage_body`] is the one-shot form for a caller that
//! already has the count. A truncated stream can end short, and a proxy can lie about the length it
//! will send.
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

/// Check the body a storage GET actually delivered, one-shot: [`StorageGet::Stored`] only when the
/// received count equals the grant. The status is `200` because the head already passed; a short
/// read or an overlong body is still a failed chunk. For a stream that is still arriving, count it
/// with [`StorageBody`] instead: it refuses the first byte past the grant, so a caller never holds
/// more than the grant for a response that lies about its length.
pub fn check_storage_body(received: u64, expected: u64) -> StorageGet {
    if received == expected {
        StorageGet::Stored
    } else {
        StorageGet::Failed { status: 200 }
    }
}

/// One storage GET's head and the bytes read from it, checked as they arrive. No client counts body
/// bytes on its own: `from_head` applies [`check_storage_get`], `push` refuses the first byte past
/// the grant, and `finish` applies [`check_storage_body`] to the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageBody {
    expected: u64,
    received: u64,
}

impl StorageBody {
    /// Start counting the body of a storage GET answer. `Err` is the head's own answer (see
    /// [`check_storage_get`]): the caller stops without reading a body.
    pub fn from_head(status: u16, content_length: Option<u64>, expected: u64) -> Result<StorageBody, StorageGet> {
        match check_storage_get(status, content_length, expected) {
            StorageGet::Stored => Ok(StorageBody { expected, received: 0 }),
            failed => Err(failed),
        }
    }

    /// Count `n` more bytes. `Err(Failed { status: 200 })` as soon as they would pass the grant, so
    /// the caller stops reading; the count is left where it was.
    pub fn push(&mut self, n: u64) -> Result<(), StorageGet> {
        let next = self.received.saturating_add(n);
        if next > self.expected {
            return Err(StorageGet::Failed { status: 200 });
        }
        self.received = next;
        Ok(())
    }

    /// The body's answer: `Stored` only when the count is exactly the grant.
    pub fn finish(self) -> StorageGet {
        check_storage_body(self.received, self.expected)
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

    #[test]
    fn a_failed_head_never_counts() {
        assert_eq!(
            StorageBody::from_head(206, Some(CHUNK), CHUNK),
            Err(StorageGet::Failed { status: 206 })
        );
        assert_eq!(
            StorageBody::from_head(200, Some(CHUNK - 1), CHUNK),
            Err(StorageGet::Failed { status: 200 }),
            "a head that declares the wrong length never starts a count"
        );
        assert_eq!(
            StorageBody::from_head(200, None, CHUNK),
            Err(StorageGet::Failed { status: 200 }),
            "no Content-Length is a failed head"
        );
        assert!(
            StorageBody::from_head(200, Some(CHUNK), CHUNK).is_ok(),
            "the exact head starts the count"
        );
    }

    #[test]
    fn push_refuses_the_first_byte_past_the_grant() {
        let mut body = StorageBody::from_head(200, Some(CHUNK), CHUNK).expect("a good head");
        assert_eq!(body.push(CHUNK), Ok(()), "the whole grant is taken");
        let mut body = StorageBody::from_head(200, Some(CHUNK), CHUNK).expect("a good head");
        assert_eq!(body.push(CHUNK / 2), Ok(()));
        assert_eq!(body.push(CHUNK / 2 + 1), Err(StorageGet::Failed { status: 200 }));
        let mut body = StorageBody::from_head(200, Some(0), 0).expect("an empty chunk");
        assert_eq!(
            body.push(1),
            Err(StorageGet::Failed { status: 200 }),
            "even one byte past zero"
        );
        assert_eq!(body.push(0), Ok(()), "zero bytes never pass the grant");
    }

    #[test]
    fn finish_is_stored_only_on_the_exact_count() {
        let mut body = StorageBody::from_head(200, Some(CHUNK), CHUNK).expect("a good head");
        body.push(CHUNK - 1).expect("inside the grant");
        assert_eq!(
            body.finish(),
            StorageGet::Failed { status: 200 },
            "a short body is not the chunk"
        );
        let mut body = StorageBody::from_head(200, Some(CHUNK), CHUNK).expect("a good head");
        body.push(CHUNK).expect("the whole grant");
        assert_eq!(body.finish(), StorageGet::Stored);
        assert_eq!(
            StorageBody::from_head(200, Some(0), 0)
                .expect("an empty chunk")
                .finish(),
            StorageGet::Stored,
            "an empty chunk is exact at zero"
        );
    }
}
