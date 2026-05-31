//! Thumbnail generation — single canonical implementation.
//!
//! All clients (iOS, Android, CLI, desktop) call `generate_thumbnail` with
//! raw RGBA pixel data. The function resizes, encodes to lossy WebP using a
//! quality cascade, and returns the first result that fits under the byte target.
//!
//! Feature flags:
//! - `webp-encode` (default): includes `generate_thumbnail` and `encode_webp`.
//!   Requires the `webp` C binding (libwebp). Disable for iOS cross-compilation
//!   targets where libwebp conflicts with aws-lc-sys. iOS generates thumbnails
//!   natively via PhotoKit/vImage and only calls `resize_for_thumbnail`.
//! - No `webp-encode`: only `resize_for_thumbnail` and the config/error types
//!   are available.

use image::{ImageBuffer, Rgba, imageops::FilterType};

/// Quality cascade step: try this (max_dimension, webp_quality) pair.
#[derive(Debug, Clone)]
pub struct LadderStep {
    pub max_dimension: u32,
    pub quality: f32,
}

/// Configuration for thumbnail generation.
#[derive(Debug, Clone)]
pub struct ThumbnailConfig {
    pub ladder: Vec<LadderStep>,
    pub target_bytes: usize,
    pub max_bytes: usize,
}

impl ThumbnailConfig {
    /// Medium variant — the default for all platforms.
    pub fn medium() -> Self {
        Self {
            ladder: vec![
                LadderStep {
                    max_dimension: 768,
                    quality: 82.0,
                },
                LadderStep {
                    max_dimension: 768,
                    quality: 74.0,
                },
                LadderStep {
                    max_dimension: 768,
                    quality: 66.0,
                },
                LadderStep {
                    max_dimension: 768,
                    quality: 58.0,
                },
                LadderStep {
                    max_dimension: 768,
                    quality: 50.0,
                },
                LadderStep {
                    max_dimension: 640,
                    quality: 58.0,
                },
                LadderStep {
                    max_dimension: 512,
                    quality: 56.0,
                },
                LadderStep {
                    max_dimension: 384,
                    quality: 54.0,
                },
            ],
            target_bytes: 100 * 1024,
            max_bytes: 128 * 1024 - 28, // server cap minus AES-GCM overhead
        }
    }

    /// Small variant — for grid views and list thumbnails.
    pub fn small() -> Self {
        Self {
            ladder: vec![
                LadderStep {
                    max_dimension: 384,
                    quality: 78.0,
                },
                LadderStep {
                    max_dimension: 384,
                    quality: 66.0,
                },
                LadderStep {
                    max_dimension: 384,
                    quality: 54.0,
                },
                LadderStep {
                    max_dimension: 320,
                    quality: 50.0,
                },
                LadderStep {
                    max_dimension: 256,
                    quality: 48.0,
                },
            ],
            target_bytes: 24 * 1024,
            max_bytes: 32 * 1024 - 28,
        }
    }

    /// Large variant — for full-screen previews (spec 031).
    pub fn large() -> Self {
        Self {
            ladder: vec![
                LadderStep {
                    max_dimension: 1600,
                    quality: 90.0,
                },
                LadderStep {
                    max_dimension: 1600,
                    quality: 82.0,
                },
                LadderStep {
                    max_dimension: 1600,
                    quality: 74.0,
                },
                LadderStep {
                    max_dimension: 1600,
                    quality: 66.0,
                },
                LadderStep {
                    max_dimension: 1600,
                    quality: 58.0,
                },
                LadderStep {
                    max_dimension: 1600,
                    quality: 50.0,
                },
            ],
            target_bytes: 400 * 1024,
            max_bytes: 480 * 1024,
        }
    }
}

/// Result of thumbnail generation.
#[derive(Debug)]
pub struct ThumbnailOutput {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub quality: f32,
    pub step_index: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ThumbnailError {
    #[error("no ladder step produced output under max_bytes")]
    AllStepsFailed,
    #[error("resize failed: {0}")]
    ResizeFailed(String),
    #[error("encode failed: {0}")]
    EncodeFailed(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Resize RGBA pixels for thumbnail use. Always available (no WebP dependency).
///
/// Returns `(resized_rgba, new_width, new_height)`. The longest side is scaled
/// to `max_dimension` preserving aspect ratio. If the source already fits,
/// the original buffer is returned unmodified.
pub fn resize_for_thumbnail(
    rgba: &[u8],
    src_width: u32,
    src_height: u32,
    max_dimension: u32,
) -> Result<(Vec<u8>, u32, u32), ThumbnailError> {
    resize_rgba(rgba, src_width, src_height, max_dimension)
}

/// Generate a WebP thumbnail from raw RGBA pixel data.
///
/// Tries each step in the config's ladder in order. Returns the first result
/// that fits under `config.target_bytes`. If none fit the target but one fits
/// under `config.max_bytes`, returns that as a fallback.
///
/// Requires feature `webp-encode`. Not available when building for iOS
/// (use `resize_for_thumbnail` + native WebP encoding instead).
#[cfg(feature = "webp-encode")]
pub fn generate_thumbnail(
    rgba: &[u8],
    src_width: u32,
    src_height: u32,
    config: &ThumbnailConfig,
) -> Result<ThumbnailOutput, ThumbnailError> {
    if rgba.len() != (src_width as usize) * (src_height as usize) * 4 {
        return Err(ThumbnailError::InvalidInput(format!(
            "expected {} bytes for {}x{} RGBA, got {}",
            (src_width as usize) * (src_height as usize) * 4,
            src_width,
            src_height,
            rgba.len()
        )));
    }

    if src_width == 0 || src_height == 0 {
        return Err(ThumbnailError::InvalidInput(
            "source dimensions must be non-zero".into(),
        ));
    }

    let mut fallback: Option<ThumbnailOutput> = None;

    for (i, step) in config.ladder.iter().enumerate() {
        let (resized, w, h) = resize_rgba(rgba, src_width, src_height, step.max_dimension)?;
        let encoded = encode_webp(&resized, w, h, step.quality)?;

        if encoded.len() <= config.target_bytes {
            return Ok(ThumbnailOutput {
                data: encoded,
                width: w,
                height: h,
                quality: step.quality,
                step_index: i,
            });
        }

        if encoded.len() <= config.max_bytes && fallback.is_none() {
            fallback = Some(ThumbnailOutput {
                data: encoded,
                width: w,
                height: h,
                quality: step.quality,
                step_index: i,
            });
        }
    }

    fallback.ok_or(ThumbnailError::AllStepsFailed)
}

/// Resize RGBA pixel data preserving aspect ratio.
///
/// The longest side is scaled to `max_dimension`. If the source is already
/// smaller than `max_dimension` on both axes, the original data is returned
/// unmodified.
fn resize_rgba(
    rgba: &[u8],
    src_width: u32,
    src_height: u32,
    max_dimension: u32,
) -> Result<(Vec<u8>, u32, u32), ThumbnailError> {
    // If source fits within max_dimension, return as-is
    if src_width <= max_dimension && src_height <= max_dimension {
        return Ok((rgba.to_vec(), src_width, src_height));
    }

    // Calculate target dimensions preserving aspect ratio
    let (dst_width, dst_height) = if src_width >= src_height {
        let scale = max_dimension as f64 / src_width as f64;
        let h = (src_height as f64 * scale).round() as u32;
        (max_dimension, h.max(1))
    } else {
        let scale = max_dimension as f64 / src_height as f64;
        let w = (src_width as f64 * scale).round() as u32;
        (w.max(1), max_dimension)
    };

    let src_img: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_raw(src_width, src_height, rgba.to_vec())
        .ok_or_else(|| ThumbnailError::ResizeFailed("failed to create image buffer from RGBA data".into()))?;

    let resized = image::imageops::resize(&src_img, dst_width, dst_height, FilterType::Lanczos3);

    Ok((resized.into_raw(), dst_width, dst_height))
}

/// Encode RGBA pixel data to lossy WebP at the given quality.
///
/// Quality is 0.0..=100.0, passed directly to libwebp.
#[cfg(feature = "webp-encode")]
fn encode_webp(rgba: &[u8], width: u32, height: u32, quality: f32) -> Result<Vec<u8>, ThumbnailError> {
    let encoder = webp::Encoder::from_rgba(rgba, width, height);
    let mem = encoder.encode(quality);
    Ok(mem.to_vec())
}

#[cfg(all(test, feature = "webp-encode"))]
mod tests {
    use super::*;

    fn make_test_rgba(w: u32, h: u32) -> Vec<u8> {
        // Create a gradient pattern so WebP has something to encode
        let mut data = Vec::with_capacity((w as usize) * (h as usize) * 4);
        for y in 0..h {
            for x in 0..w {
                data.push((x % 256) as u8); // R
                data.push((y % 256) as u8); // G
                data.push(((x + y) % 256) as u8); // B
                data.push(255); // A
            }
        }
        data
    }

    #[test]
    fn medium_config_produces_output() {
        let rgba = make_test_rgba(1024, 768);
        let result = generate_thumbnail(&rgba, 1024, 768, &ThumbnailConfig::medium()).unwrap();
        assert!(result.data.len() <= ThumbnailConfig::medium().max_bytes);
        assert!(result.width <= 768);
        assert!(result.height <= 768);
    }

    #[test]
    fn small_config_produces_output() {
        let rgba = make_test_rgba(800, 600);
        let result = generate_thumbnail(&rgba, 800, 600, &ThumbnailConfig::small()).unwrap();
        assert!(result.data.len() <= ThumbnailConfig::small().max_bytes);
        assert!(result.width <= 384);
    }

    #[test]
    fn large_config_produces_output() {
        let rgba = make_test_rgba(2000, 1500);
        let result = generate_thumbnail(&rgba, 2000, 1500, &ThumbnailConfig::large()).unwrap();
        assert!(result.data.len() <= ThumbnailConfig::large().max_bytes);
        assert!(result.width <= 1600);
    }

    #[test]
    fn rejects_wrong_buffer_size() {
        let rgba = vec![0u8; 100]; // wrong size for 10x10 (needs 400)
        let result = generate_thumbnail(&rgba, 10, 10, &ThumbnailConfig::medium());
        assert!(result.is_err());
        assert!(
            matches!(result, Err(ThumbnailError::InvalidInput(_))),
            "expected InvalidInput error"
        );
    }

    #[test]
    fn small_source_not_upscaled() {
        let rgba = make_test_rgba(200, 150);
        let result = generate_thumbnail(&rgba, 200, 150, &ThumbnailConfig::medium()).unwrap();
        assert_eq!(result.width, 200);
        assert_eq!(result.height, 150);
    }

    #[test]
    fn aspect_ratio_preserved_landscape() {
        let rgba = make_test_rgba(2000, 1000);
        let result = generate_thumbnail(&rgba, 2000, 1000, &ThumbnailConfig::medium()).unwrap();
        // Longest side (2000) scaled to 768, so width=768 height=384
        assert_eq!(result.width, 768);
        assert_eq!(result.height, 384);
    }

    #[test]
    fn aspect_ratio_preserved_portrait() {
        let rgba = make_test_rgba(1000, 2000);
        let result = generate_thumbnail(&rgba, 1000, 2000, &ThumbnailConfig::medium()).unwrap();
        // Longest side (2000) scaled to 768, so height=768 width=384
        assert_eq!(result.height, 768);
        assert_eq!(result.width, 384);
    }

    #[test]
    fn output_is_valid_webp() {
        let rgba = make_test_rgba(500, 500);
        let result = generate_thumbnail(&rgba, 500, 500, &ThumbnailConfig::medium()).unwrap();
        // WebP files start with RIFF header
        assert!(
            result.data.len() >= 4 && result.data[..4] == *b"RIFF",
            "output should start with RIFF header"
        );
    }

    #[test]
    fn zero_dimensions_rejected() {
        let result = generate_thumbnail(&[], 0, 0, &ThumbnailConfig::medium());
        assert!(result.is_err());
    }
}
