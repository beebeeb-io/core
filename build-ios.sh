#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$SCRIPT_DIR/beebeeb-uniffi"
BINDINGS_DIR="$CRATE_DIR/bindings"
TARGET_DIR="$SCRIPT_DIR/target"
OUTPUT_XCFW="$SCRIPT_DIR/BeebeebCore.xcframework"
OUTPUT_SWIFT="$SCRIPT_DIR/BeebeebCore.swift"

echo "=== Beebeeb iOS xcframework build ==="
echo ""

# Ensure targets are installed
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  if ! rustup target list --installed | grep -q "$target"; then
    echo "Installing Rust target: $target"
    rustup target add "$target"
  fi
done

# Regenerate Swift bindings + C header from current Rust source before the
# iOS cross-builds. This step exists because the previous flow only *copied*
# committed `bindings/` files into the xcframework, so any drift between
# `src/lib.rs` and `bindings/` produced an xcframework whose header didn't
# match the .a binary. Surfaced during 0426: `decrypt_chunks_to_file`,
# `download_and_decrypt_file`, and the `FileProviderCacheHandle` methods
# were defined in Rust but absent from the committed `bindings/`, causing
# 12 "cannot find symbol" errors at app-link time. Regenerating here keeps
# `bindings/` byte-for-byte in sync with the dylib uniffi-bindgen sees.
echo ""
echo "[0/3] Regenerating Swift bindings from current Rust source..."
cargo build -p beebeeb-uniffi --release
cargo run -p beebeeb-uniffi --features cli --bin uniffi-bindgen -- \
    generate \
    --library "$TARGET_DIR/release/libbeebeeb_uniffi.dylib" \
    --language swift \
    --out-dir "$BINDINGS_DIR"

# Build device (arm64)
# Pass --no-default-features so Cargo does not unify beebeeb-core's webp-encode
# feature from other workspace members. The webp crate (C libwebp binding)
# conflicts with aws-lc-sys during iOS cross-compilation. iOS generates WebP
# thumbnails natively via PhotoKit/vImage using the always-available
# resize_for_thumbnail UniFFI export instead.
echo "[1/3] Building aarch64-apple-ios (device)..."
cargo build -p beebeeb-uniffi --target aarch64-apple-ios --release --no-default-features

# Build simulator arm64
echo "[2/3] Building aarch64-apple-ios-sim (simulator arm64)..."
cargo build -p beebeeb-uniffi --target aarch64-apple-ios-sim --release --no-default-features

# Build simulator x86_64
echo "[3/3] Building x86_64-apple-ios (simulator x86_64)..."
cargo build -p beebeeb-uniffi --target x86_64-apple-ios --release --no-default-features

# Merge simulator slices into a fat binary
DEVICE_LIB="$TARGET_DIR/aarch64-apple-ios/release/libbeebeeb_uniffi.a"
SIM_ARM64_LIB="$TARGET_DIR/aarch64-apple-ios-sim/release/libbeebeeb_uniffi.a"
SIM_X86_LIB="$TARGET_DIR/x86_64-apple-ios/release/libbeebeeb_uniffi.a"
SIM_FAT_LIB="$TARGET_DIR/libbeebeeb_uniffi_sim_fat.a"

echo ""
echo "[lipo] Merging simulator slices..."
lipo -create "$SIM_ARM64_LIB" "$SIM_X86_LIB" -output "$SIM_FAT_LIB"

# Strip debug + local symbols from the device staticlib and simulator fat.
# `cargo`'s `strip = "symbols"` does not reliably strip `.a` archives, so we
# do it here after lipo. `2>/dev/null` swallows the harmless
# "already stripped" warnings for tiny upstream objects.
echo ""
echo "[strip] Stripping debug + local symbols from staticlibs..."
strip -x -S "$DEVICE_LIB" 2>/dev/null || true
strip -x -S "$SIM_FAT_LIB" 2>/dev/null || true

# Copy headers into a staging dir (xcodebuild -create-xcframework requires a headers dir)
HEADERS_DIR="$TARGET_DIR/xcframework-headers"
rm -rf "$HEADERS_DIR"
mkdir -p "$HEADERS_DIR"
cp "$BINDINGS_DIR/beebeeb_uniffiFFI.h" "$HEADERS_DIR/"
# xcodebuild expects the module map to be named module.modulemap
cp "$BINDINGS_DIR/beebeeb_uniffiFFI.modulemap" "$HEADERS_DIR/module.modulemap"

# Create xcframework
echo "[xcodebuild] Creating BeebeebCore.xcframework..."
rm -rf "$OUTPUT_XCFW"
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB"  -headers "$HEADERS_DIR" \
  -library "$SIM_FAT_LIB" -headers "$HEADERS_DIR" \
  -output "$OUTPUT_XCFW"

# Copy Swift bindings alongside for use by the Expo module
cp "$BINDINGS_DIR/beebeeb_uniffi.swift" "$OUTPUT_SWIFT"

echo ""
echo "=== Build complete ==="
echo ""
echo "Outputs:"
echo "  $OUTPUT_XCFW"
echo "  $OUTPUT_SWIFT"
echo ""
echo "xcframework contents:"
find "$OUTPUT_XCFW" -maxdepth 3 | sort
