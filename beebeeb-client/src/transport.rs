use std::{future::Future, pin::Pin, time::Duration};

use beebeeb_api::{Answer, Header, Method, Request};

pub(crate) fn validate_api_base(api_base: &str) -> Result<url::Url, TransportError> {
    let base = url::Url::parse(api_base).map_err(|_| TransportError::Configuration)?;
    let host = base.host_str().ok_or(TransportError::Configuration)?;
    let loopback_http = base.scheme() == "http" && matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
    if base.scheme() == "https" || loopback_http {
        Ok(base)
    } else {
        Err(TransportError::Configuration)
    }
}

pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<Answer, TransportError>> + Send + 'a>>;
pub type TransportStreamFuture<'a> = Pin<Box<dyn Future<Output = Result<StreamResponse, TransportError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    pub max_event_bytes: usize,
    pub max_events: usize,
    pub max_stream_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBatch {
    pub events: Vec<Vec<u8>>,
    /// `false` means the transport returned after reaching `max_events` while
    /// the server stream was still open.
    pub ended: bool,
}

/// A stream transport must preserve a non-success HTTP answer so the common
/// client layer can apply account-mismatch and session-expiry policy.
#[derive(Debug)]
pub enum StreamResponse {
    Batch(StreamBatch),
    Http(Answer),
}

pub trait Transport: Send + Sync {
    fn send<'a>(&'a self, request: Request, max_response_bytes: usize) -> TransportFuture<'a>;

    /// A body whose total duration is unbounded while bytes keep arriving.
    /// Native transports enforce `idle_timeout` between body chunks.
    fn send_progress<'a>(
        &'a self,
        request: Request,
        max_response_bytes: usize,
        _idle_timeout: Duration,
    ) -> TransportFuture<'a> {
        self.send(request, max_response_bytes)
    }

    fn stream<'a>(&'a self, request: Request, limits: StreamLimits) -> TransportStreamFuture<'a> {
        Box::pin(async move {
            let answer = self.send(request, limits.max_stream_bytes).await?;
            if !(200..=299).contains(&answer.status) {
                return Ok(StreamResponse::Http(answer));
            }
            decode_sse(&answer.body, limits).map(StreamResponse::Batch)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("transport configuration is invalid")]
    Configuration,
    #[error("the request could not be sent")]
    Network,
    #[error("the response exceeded its size limit")]
    ResponseTooLarge,
    #[error("the response contained an invalid header")]
    InvalidHeader,
    #[error("a stream event exceeded its size limit")]
    EventTooLarge,
    #[error("the stream exceeded its size limit")]
    StreamTooLarge,
    #[error("the stream framing was invalid")]
    InvalidStream,
}

pub fn decode_sse(body: &[u8], limits: StreamLimits) -> Result<StreamBatch, TransportError> {
    if limits.max_event_bytes == 0 || limits.max_events == 0 || limits.max_stream_bytes == 0 {
        return Err(TransportError::Configuration);
    }
    if body.len() > limits.max_stream_bytes {
        return Err(TransportError::StreamTooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| TransportError::InvalidStream)?;
    let ended_cleanly = text.is_empty() || text.ends_with("\n\n") || text.ends_with("\r\n\r\n");
    if !ended_cleanly {
        return Err(TransportError::InvalidStream);
    }
    let normalized = text.replace("\r\n", "\n");
    let mut events = Vec::new();
    for frame in normalized.split("\n\n") {
        if frame.is_empty() {
            continue;
        }
        let mut data = Vec::new();
        for line in frame.lines() {
            let Some(value) = line.strip_prefix("data:") else {
                continue;
            };
            let value = value.strip_prefix(' ').unwrap_or(value).as_bytes();
            let joined = data
                .len()
                .checked_add(value.len())
                .ok_or(TransportError::EventTooLarge)?;
            if joined > limits.max_event_bytes {
                return Err(TransportError::EventTooLarge);
            }
            if !data.is_empty() {
                data.push(b'\n');
            }
            data.extend_from_slice(value);
        }
        if data.is_empty() {
            continue;
        }
        events.push(data);
        if events.len() == limits.max_events {
            return Ok(StreamBatch { events, ended: false });
        }
    }
    Ok(StreamBatch { events, ended: true })
}

#[cfg(feature = "native-transport")]
pub struct ReqwestTransport {
    base: reqwest::Url,
    client: reqwest::Client,
    progress_client: reqwest::Client,
}

#[cfg(feature = "native-transport")]
impl ReqwestTransport {
    pub fn new(api_base: &str) -> Result<Self, TransportError> {
        let mut base = validate_api_base(api_base)?;
        base.set_path("/");
        base.set_query(None);
        base.set_fragment(None);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| TransportError::Configuration)?;
        let progress_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| TransportError::Configuration)?;
        Ok(Self {
            base,
            client,
            progress_client,
        })
    }

    fn outgoing(&self, request: &Request) -> Result<reqwest::RequestBuilder, TransportError> {
        self.outgoing_with(&self.client, request)
    }

    fn outgoing_with(
        &self,
        client: &reqwest::Client,
        request: &Request,
    ) -> Result<reqwest::RequestBuilder, TransportError> {
        let path = request.path().strip_prefix('/').ok_or(TransportError::Configuration)?;
        let url = self.base.join(path).map_err(|_| TransportError::Configuration)?;
        let method = match request.method() {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Patch => reqwest::Method::PATCH,
            Method::Delete => reqwest::Method::DELETE,
        };
        let mut outgoing = client.request(method, url);
        for header in request.headers() {
            outgoing = outgoing.header(&header.name, &header.value);
        }
        Ok(outgoing.body(request.body().to_vec()))
    }
}

#[cfg(feature = "native-transport")]
impl Transport for ReqwestTransport {
    fn send<'a>(&'a self, request: Request, max_response_bytes: usize) -> TransportFuture<'a> {
        Box::pin(async move {
            let mut response = self
                .outgoing(&request)?
                .send()
                .await
                .map_err(|_| TransportError::Network)?;
            let status = response.status().as_u16();
            let mut headers = Vec::with_capacity(response.headers().len());
            for (name, value) in response.headers() {
                headers.push(Header::new(
                    name.as_str(),
                    value.to_str().map_err(|_| TransportError::InvalidHeader)?,
                ));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| TransportError::Network)? {
                let new_len = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(TransportError::ResponseTooLarge)?;
                if new_len > max_response_bytes {
                    return Err(TransportError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Answer::new(status, headers, body))
        })
    }

    fn send_progress<'a>(
        &'a self,
        request: Request,
        max_response_bytes: usize,
        idle_timeout: Duration,
    ) -> TransportFuture<'a> {
        Box::pin(async move {
            let mut response = self
                .outgoing_with(&self.progress_client, &request)?
                .send()
                .await
                .map_err(|_| TransportError::Network)?;
            let status = response.status().as_u16();
            let mut headers = Vec::with_capacity(response.headers().len());
            for (name, value) in response.headers() {
                headers.push(Header::new(
                    name.as_str(),
                    value.to_str().map_err(|_| TransportError::InvalidHeader)?,
                ));
            }
            let mut body = Vec::new();
            loop {
                let chunk = tokio::time::timeout(idle_timeout, response.chunk())
                    .await
                    .map_err(|_| TransportError::Network)?
                    .map_err(|_| TransportError::Network)?;
                let Some(chunk) = chunk else { break };
                let new_len = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(TransportError::ResponseTooLarge)?;
                if new_len > max_response_bytes {
                    return Err(TransportError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Answer::new(status, headers, body))
        })
    }

    fn stream<'a>(&'a self, request: Request, limits: StreamLimits) -> TransportStreamFuture<'a> {
        Box::pin(async move {
            if limits.max_event_bytes == 0 || limits.max_events == 0 || limits.max_stream_bytes == 0 {
                return Err(TransportError::Configuration);
            }
            let mut response = self
                .outgoing_with(&self.progress_client, &request)?
                .send()
                .await
                .map_err(|_| TransportError::Network)?;
            if !response.status().is_success() {
                let status = response.status().as_u16();
                let mut headers = Vec::with_capacity(response.headers().len());
                for (name, value) in response.headers() {
                    headers.push(Header::new(
                        name.as_str(),
                        value.to_str().map_err(|_| TransportError::InvalidHeader)?,
                    ));
                }
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| TransportError::Network)? {
                    let new_len = body
                        .len()
                        .checked_add(chunk.len())
                        .ok_or(TransportError::StreamTooLarge)?;
                    if new_len > limits.max_stream_bytes {
                        return Err(TransportError::StreamTooLarge);
                    }
                    body.extend_from_slice(&chunk);
                }
                return Ok(StreamResponse::Http(Answer::new(status, headers, body)));
            }
            let mut seen = 0usize;
            let mut pending = Vec::new();
            let mut events = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| TransportError::Network)? {
                seen = seen.checked_add(chunk.len()).ok_or(TransportError::StreamTooLarge)?;
                if seen > limits.max_stream_bytes {
                    return Err(TransportError::StreamTooLarge);
                }
                pending.extend_from_slice(&chunk);
                while let Some(frame_end) = sse_frame_end(&pending) {
                    let frame: Vec<u8> = pending.drain(..frame_end).collect();
                    let batch = decode_sse(
                        &frame,
                        StreamLimits {
                            max_event_bytes: limits.max_event_bytes,
                            max_events: 1,
                            max_stream_bytes: frame_end,
                        },
                    )?;
                    events.extend(batch.events);
                    if events.len() >= limits.max_events {
                        events.truncate(limits.max_events);
                        return Ok(StreamResponse::Batch(StreamBatch { events, ended: false }));
                    }
                }
                if pending.len() > limits.max_event_bytes.saturating_add(4096) {
                    return Err(TransportError::EventTooLarge);
                }
            }
            if !pending.is_empty() {
                return Err(TransportError::InvalidStream);
            }
            Ok(StreamResponse::Batch(StreamBatch { events, ended: true }))
        })
    }
}

fn sse_frame_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| index + 2)
        .or_else(|| {
            bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
        })
}
