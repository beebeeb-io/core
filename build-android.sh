#!/usr/bin/env bash
# Build beebeeb-uniffi for Android: .so files for all ABIs + Kotlin bindings.
#
# Requirements:
#   - Android NDK installed (r25c+ recommended)
#   - ANDROID_NDK_HOME or NDK_HOME pointing to the NDK root
#   - cargo-ndk: cargo install cargo-ndk
#   - Android targets: rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# Usage:
#   export ANDROID_NDK_HOME=/path/to/ndk
#   bash build-android.sh [--debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROFILE="release"
CARGO_PROFILE_FLAG="--release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="debug"
    CARGO_PROFILE_FLAG=""
fi

# ---------------------------------------------------------------------------
# 1. Prerequisite checks
# ---------------------------------------------------------------------------

if ! command -v cargo-ndk &>/dev/null; then
    echo "ERROR: cargo-ndk not found. Install with: cargo install cargo-ndk"
    exit 1
fi

NDK_ROOT="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
if [[ -z "$NDK_ROOT" ]]; then
    echo "ERROR: Android NDK not found."
    echo "  Set ANDROID_NDK_HOME or NDK_HOME to your NDK installation path."
    echo "  Install NDK via Android Studio → SDK Manager → SDK Tools → NDK."
    echo ""
    echo "  Example:"
    echo "    export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/25.2.9519653"
    echo "    bash build-android.sh"
    exit 1
fi

echo "Using NDK: $NDK_ROOT"
echo "Profile: $PROFILE"
echo ""

# ---------------------------------------------------------------------------
# 2. Build .so for all three ABIs
# ---------------------------------------------------------------------------

echo "Building for Android ABIs..."
cargo ndk \
    -t armeabi-v7a \
    -t arm64-v8a \
    -t x86_64 \
    -o jniLibs \
    build -p beebeeb-uniffi $CARGO_PROFILE_FLAG

echo ""
echo "Built .so files:"
find jniLibs -name "*.so" | sort

# ---------------------------------------------------------------------------
# 3. Build the library in debug mode for uniffi-bindgen (host target)
# ---------------------------------------------------------------------------

echo ""
echo "Building host library for Kotlin binding generation..."
cargo build -p beebeeb-uniffi

# ---------------------------------------------------------------------------
# 4. Generate Kotlin bindings
# ---------------------------------------------------------------------------

echo ""
echo "Generating Kotlin bindings..."
mkdir -p bindings/kotlin

cargo run --bin uniffi-bindgen -- generate \
    --library target/debug/libbeebeeb_uniffi.dylib \
    --language kotlin \
    --out-dir bindings/kotlin/ 2>/dev/null || \
cargo run --bin uniffi-bindgen -- generate \
    --library target/debug/libbeebeeb_uniffi.so \
    --language kotlin \
    --out-dir bindings/kotlin/

echo ""
echo "Kotlin bindings:"
find bindings/kotlin -type f | sort

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------

echo ""
echo "Android build complete."
echo ""
echo "Output:"
echo "  jniLibs/              — .so files for Expo/Gradle (jniLibs structure)"
echo "  bindings/kotlin/      — Kotlin UniFFI wrapper"
echo ""
echo "Gradle integration:"
echo "  Copy jniLibs/ into your Android module's src/main/ directory."
echo "  Copy bindings/kotlin/ sources into your module's src/main/java/ directory."
