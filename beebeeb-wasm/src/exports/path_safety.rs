//! Move 11's naming rules, for the web client that writes server-provided names
//! (and archive entries) to a local tree.
//!
//! The rules are the pure, wasm-safe half of `beebeeb_core::path_safety`. The
//! filesystem half (`ensure_contained`, `safe_child`, `safe_rel_join`,
//! `default_output_path`) is `#[cfg(not(target_arch = "wasm32"))]` in core — a
//! browser has no symlinks or local paths — so it is deliberately not exported
//! here. Vectors for it stay in the core test suite.
use beebeeb_core::path_safety::{self, Rules};
use wasm_bindgen::prelude::*;

/// Check one server-provided name (a single component, never a path).
///
/// `portable` selects the strict cross-platform rule set (what a pulled tree or
/// an archive must satisfy); `windows` says the caller will write it with
/// Windows path semantics. Returns normally when the name is safe, throws the
/// user-facing reason otherwise (e.g. `contains a path separator`).
#[wasm_bindgen(js_name = checkPathComponent)]
pub fn check_path_component(name: &str, portable: bool, windows: bool) -> Result<(), JsError> {
    path_safety::check_component_for(name, portable, windows).map_err(unsafe_name)
}

/// Rewrite one name so it is safe under the strictest (Windows) rule set:
/// `: < > " | ? *` become `_`, trailing dots/spaces become `_`, a reserved
/// device name gets a leading `_`, and bidi controls are removed. A name that
/// is structurally unsafe (separator, `.`/`..`, control character, drive
/// prefix) is still refused, never rewritten.
#[wasm_bindgen(js_name = sanitizePathComponent)]
pub fn sanitize_path_component(name: &str) -> Result<String, JsError> {
    path_safety::sanitize_component(name, Rules::Portable).map_err(unsafe_name)
}

/// The archive/extract rule: [`path_safety::archive_component`], the portable
/// sanitizer above. Named for the caller that extracts entries, so the intent is
/// on the call site; it never drops a name silently.
#[wasm_bindgen(js_name = archiveEntryName)]
pub fn archive_entry_name(name: &str) -> Result<String, JsError> {
    path_safety::archive_component(name).map_err(unsafe_name)
}

fn unsafe_name(error: path_safety::UnsafeName) -> JsError {
    JsError::new(&error.to_string())
}