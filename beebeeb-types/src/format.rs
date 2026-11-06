//! One byte formatter for every client.
//!
//! Three honest units and no hidden policy:
//!
//! - [`format_si`] — decimal units (1 KB = 1,000 B). This is the canonical
//!   storage form: 0 decimals below a terabyte, 1 decimal from it, truncated
//!   (never rounded up) below it. Its bytes are the ones
//!   `quota::format_storage_si` has always returned; that function is now a
//!   re-export of this one.
//! - [`format_binary`] — binary units (1 KiB = 1,024 B) with IEC labels.
//! - [`format_compact`] — decimal units with an explicit decimal count, for
//!   dense tables. A value that rounds up to the next unit is carried
//!   ("999.6 KB" with one decimal prints "1.0 MB", never "1000.0 KB").
//!
//! None of them clamp or substitute: a caller that wants "—" for a negative
//! or "0 B" for a zero guards before calling. Formatting what it was given is
//! the only way a display bug can be traced back to a number. A negative
//! count therefore keeps its sign and never scales (`-1500 B`, not `-1.5 KB`),
//! which is the frozen `format_storage_si` rule applied to all three.

/// Decimal units: 1 KB = 1,000 B.
pub const SI_BASE: u64 = 1_000;
/// Binary units: 1 KiB = 1,024 B.
pub const IEC_BASE: u64 = 1_024;

const SI_UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
const IEC_UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatPrecisionError {
    pub requested: usize,
    pub maximum: usize,
}

impl std::fmt::Display for FormatPrecisionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "format precision {} exceeds maximum {}",
            self.requested, self.maximum
        )
    }
}

impl std::error::Error for FormatPrecisionError {}

/// Formats a byte count in decimal units, the canonical storage form.
///
/// Byte-identical to the historical `quota::format_storage_si`: `0 B`,
/// `999 B`, `1 KB` (1,000), `1 MB`, `1 GB`, `1.0 TB` (1,000,000,000,000).
/// Negative counts keep their sign (`-5 B`).
pub fn format_si(bytes: i64) -> String {
    if bytes < 1_000 {
        return format!("{bytes} B");
    }
    if bytes < 1_000_000 {
        return format!("{} KB", bytes / 1_000);
    }
    if bytes < 1_000_000_000 {
        return format!("{} MB", bytes / 1_000_000);
    }
    if bytes < 1_000_000_000_000 {
        return format!("{} GB", bytes / 1_000_000_000);
    }
    let tb = bytes as f64 / 1_000_000_000_000.0;
    format!("{tb:.1} TB")
}

/// Formats a byte count in binary units with IEC labels.
///
/// Same ladder and precision rule as [`format_si`], on 1,024: `1 KiB` (1,024),
/// `1 MiB`, `1 GiB`, `1.0 TiB` (1,099,511,627,776).
pub fn format_binary(bytes: i64) -> String {
    let kib = IEC_BASE as i64;
    if bytes < kib {
        return format!("{} {}", bytes, IEC_UNITS[0]);
    }
    let mib = IEC_BASE.pow(2) as i64;
    if bytes < mib {
        return format!("{} {}", bytes / kib, IEC_UNITS[1]);
    }
    let gib = IEC_BASE.pow(3) as i64;
    if bytes < gib {
        return format!("{} {}", bytes / mib, IEC_UNITS[2]);
    }
    let tib = IEC_BASE.pow(4) as i64;
    if bytes < tib {
        return format!("{} {}", bytes / gib, IEC_UNITS[3]);
    }
    let value = bytes as f64 / tib as f64;
    format!("{value:.1} {}", IEC_UNITS[4])
}

/// Formats a byte count in decimal units with an explicit number of decimals.
///
/// Built for dense tables: the caller picks 0, 1 or 2 decimals, and a value
/// that rounds up to the next unit is carried into it. Byte counts below
/// 1,000 always print as `N B` with no decimals.
pub fn format_compact(bytes: i64, decimals: usize) -> String {
    format_compact_inner(bytes, decimals.min(crate::limits::MAX_FORMAT_PRECISION))
}

/// Rejecting form for binding and caller values.
pub fn try_format_compact(bytes: i64, decimals: usize) -> Result<String, FormatPrecisionError> {
    if decimals > crate::limits::MAX_FORMAT_PRECISION {
        return Err(FormatPrecisionError {
            requested: decimals,
            maximum: crate::limits::MAX_FORMAT_PRECISION,
        });
    }
    Ok(format_compact_inner(bytes, decimals))
}

fn format_compact_inner(bytes: i64, decimals: usize) -> String {
    if bytes < SI_BASE as i64 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while unit + 1 < SI_UNITS.len() && value.abs() >= 1_000.0 {
        value /= 1_000.0;
        unit += 1;
    }
    let mut text = format!("{value:.decimals$}");
    // 999.6 KB at one decimal rounds to 1000.0, which is 1.0 MB.
    if unit + 1 < SI_UNITS.len() && text.trim_start_matches('-').parse::<f64>().unwrap_or(0.0) >= 1_000.0 {
        value /= 1_000.0;
        unit += 1;
        text = format!("{value:.decimals$}");
    }
    format!("{text} {}", SI_UNITS[unit])
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn excessive_precision_is_rejected_and_convenience_form_is_bounded() {
        assert!(try_format_compact(1_000, 3).is_err());
        assert!(try_format_compact(1_000, usize::MAX).is_err());
        assert_eq!(format_compact(1_000, usize::MAX), "1.00 KB");
    }
}
