//! Onboarding logic shared by every client (task 1744, epic 1725).
//!
//! The server declares what onboarding requires (numbers, steps, order); the
//! clients render it; the logic that must be identical everywhere lives here:
//!
//! - [`password`]: policy evaluator driven by the server's numbers.
//! - [`breach`]: k-anonymity breached-password helper (hashing and matching
//!   only; the HTTP call stays in each client).
//! - [`ceremony`]: the signup state machine over the existing recovery-phrase
//!   and OPAQUE primitives.
//!
//! Nothing here performs I/O and nothing here implements a new cryptographic
//! primitive. Exposed to web through `beebeeb-wasm` and to iOS/Android/desktop
//! through `beebeeb-uniffi`.

pub mod breach;
pub mod ceremony;
pub mod password;

pub use breach::{BreachQuery, BreachResponse, BreachVerdict, evaluate_breach_response};
pub use ceremony::{
    CeremonyConfig, CeremonyError, CeremonyStep, RegistrationFinish, RegistrationStart, SignupCeremony,
    VERIFY_WORD_COUNT_FLOOR,
};
pub use password::{
    MIN_LENGTH_FLOOR, PasswordEvaluation, PasswordHint, PasswordPolicy, PasswordStrength, evaluate_password,
};
