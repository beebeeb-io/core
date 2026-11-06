//! Move 1's byte formatting, beside the existing `storage_format_si`.
//!
//! `storage_format_si` (unchanged, in `lib.rs`) is the SI formatter. These two
//! add the binary form and the explicit-precision form from the same module, so
//! the web client stops carrying its own rounding rules.
use wasm_bindgen::prelude::*;

/// Format a byte count with binary units and IEC labels: `1 KiB` (1,024),
/// `1 MiB`, `1.0 TiB`. Same ladder and precision rule as the SI formatter; a
/// negative count keeps its sign and never scales (`-1500 B`).
#[wasm_bindgen(js_name = formatBinary)]
pub fn format_binary(bytes: i64) -> String {
    beebeeb_types::format_binary(bytes)
}

/// Format a byte count in decimal units with `decimals` decimals (0, 1 or 2),
/// carrying a value that rounds up into the next unit (`999.6 KB` with one
/// decimal prints `1.0 MB`). Counts below 1,000 always print as `N B`.
#[wasm_bindgen(js_name = formatCompact)]
pub fn format_compact(bytes: i64, decimals: u32) -> Result<String, JsError> {
    let decimals = usize::try_from(decimals).map_err(|_| JsError::new("format precision does not fit usize"))?;
    beebeeb_types::try_format_compact(bytes, decimals).map_err(|error| JsError::new(&error.to_string()))
}
