//! I/O-free request descriptions, answer parsing, and account flows.
//!
//! This crate deliberately has no transport or filesystem dependency. A caller
//! sends [`Request`] with its platform HTTP stack and returns an [`Answer`].

mod answer;
mod endpoint;
mod request;

pub mod flows;
pub mod proposed;
pub mod routes;

pub use answer::{Answer, ApiError};
pub use endpoint::{Endpoint, RawEndpoint};
pub use request::{ClientIdentity, Header, Method, Request, RequestBuilder};
