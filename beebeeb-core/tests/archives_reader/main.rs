//! The archive reader's test binary: detection, names, tar, zip, passwords.
//!
//! One module per concern; `support` holds the fixture builders shared by
//! them. Every fixture is built in the test (bombs are never committed).

mod detect;
mod names;
mod password;
mod support;
mod tar;
mod zip;
