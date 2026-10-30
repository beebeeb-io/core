//! Test seams of the transfer driver (feature `test-support`): the scripted
//! transport the lib tests use, and the conformance suite a client runs
//! against its real transport.

pub mod conformance;
pub mod scripted;

pub use conformance::{CheckResult, ConformanceReport};
pub use scripted::{Gate, Recorded, Reply, Request, ScriptedIo, WALL_START_MS};
