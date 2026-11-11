use std::{fmt, future::Future, path::Path, pin::Pin};

pub type ChunkTransportFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ChunkTransportError>> + Send + 'a>>;

/// A signed storage location. Its secret-bearing value is available only to
/// the platform adapter that has to execute the request.
#[derive(Clone, PartialEq, Eq)]
pub struct ChunkLocation(String);

impl ChunkLocation {
    pub fn new(value: impl Into<String>) -> Result<Self, ChunkTransportError> {
        let value = value.into();
        if !value.starts_with("https://") {
            return Err(ChunkTransportError::InvalidRequest);
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ChunkLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChunkLocation(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChunkTransportError {
    #[error("the chunk request is invalid")]
    InvalidRequest,
    #[error("the chunk transport is unavailable")]
    Unavailable,
    #[error("the chunk response exceeded its bound")]
    ResponseTooLarge,
}

/// OS-facing storage seam for presigned URLs and background task cancellation.
/// Errors deliberately carry no URL or lower-level error string.
pub trait ChunkTransport: Send + Sync {
    fn upload_file<'a>(
        &'a self,
        location: &'a ChunkLocation,
        headers: &'a [(String, String)],
        body_path: &'a Path,
    ) -> ChunkTransportFuture<'a, u16>;

    fn download_range<'a>(
        &'a self,
        location: &'a ChunkLocation,
        range: Option<(u64, u64)>,
        max_bytes: usize,
    ) -> ChunkTransportFuture<'a, Vec<u8>>;

    fn cancel_background(&self, tickets: &[String]) -> Result<(), ChunkTransportError>;
}
