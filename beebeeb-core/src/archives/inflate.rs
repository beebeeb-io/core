//! Raw deflate, push-style: input in, bounded output out. Shared by gzip
//! members and zip entries; no I/O, so a decoder can stop for bytes and go
//! on exactly where it was.

use flate2::{Decompress, FlushDecompress, Status};

pub(crate) struct Inflater {
    inner: Decompress,
}

/// One push: how much input went in, and whether the stream ended.
pub(crate) struct Pushed {
    pub consumed: usize,
    pub produced: usize,
    pub stream_end: bool,
}

impl Inflater {
    pub(crate) fn new() -> Self {
        Self {
            inner: Decompress::new(false),
        }
    }

    /// Feed `input`; append at most `room` bytes of output to `out`.
    /// `Err(())` is a corrupt deflate stream.
    pub(crate) fn push(&mut self, input: &[u8], out: &mut Vec<u8>, room: usize) -> Result<Pushed, ()> {
        let start = out.len();
        out.resize(start + room, 0);
        let (in_before, out_before) = (self.inner.total_in(), self.inner.total_out());
        let status = self.inner.decompress(input, &mut out[start..], FlushDecompress::None);
        let consumed = (self.inner.total_in() - in_before) as usize;
        let produced = (self.inner.total_out() - out_before) as usize;
        out.truncate(start + produced);
        match status {
            Ok(Status::StreamEnd) => Ok(Pushed {
                consumed,
                produced,
                stream_end: true,
            }),
            Ok(Status::Ok | Status::BufError) => Ok(Pushed {
                consumed,
                produced,
                stream_end: false,
            }),
            Err(_) => Err(()),
        }
    }
}
