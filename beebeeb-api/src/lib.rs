//! I/O-free request descriptions, answer parsing, and account flows.
//!
//! This crate deliberately has no transport or filesystem dependency. A caller
//! sends [`Request`] with its platform HTTP stack and returns an [`Answer`].

/// `Debug` for a wire record: the listed public fields as they are, and
/// `[REDACTED]` for the secret ones (tokens, tickets, codes, passphrases,
/// authenticator secrets). Crypto review, P2-5.
macro_rules! redacted_debug {
    ($ty:ident; show: [$($shown:ident),* $(,)?]; hide: [$($hidden:ident),* $(,)?]) => {
        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($shown), &self.$shown))*
                    $(.field(stringify!($hidden), &"[REDACTED]"))*
                    .finish()
            }
        }
    };
}
pub(crate) use redacted_debug;

mod answer;
mod endpoint;
mod request;

pub mod flows;
pub mod proposed;
pub mod routes;

pub use answer::{Answer, ApiError};
pub use endpoint::{Endpoint, RawEndpoint};
pub use request::{ClientIdentity, Header, Method, Request, RequestBuilder};
