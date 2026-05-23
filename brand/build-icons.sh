#!/usr/bin/env bash
# build-icons.sh — regenerate all platform icons from logo-mark.svg
#
# Single source of truth: repos/core/brand/logo-mark.svg.
# Run this any time the mark changes. Output goes to each client's icon
# directory directly so the next build picks it up.
#
# Requires: rsvg-convert (brew install librsvg)
#
# Usage:  cd repos/core/brand && ./build-icons.sh
#         (or from anywhere: ./repos/core/brand/build-icons.sh)

set -euo pipefail

# Resolve paths relative to this script, so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
MARK="$SCRIPT_DIR/logo-mark.svg"
MARK_DARK="$SCRIPT_DIR/logo-mark-dark.svg"

if ! command -v rsvg-convert >/dev/null 2>&1; then
  echo "error: rsvg-convert not found. install with: brew install librsvg" >&2
  exit 1
fi

if [ ! -f "$MARK" ]; then
  echo "error: missing $MARK" >&2
  exit 1
fi

render() {
  local size="$1" src="$2" out="$3"
  rsvg-convert -w "$size" -h "$size" "$src" -o "$out"
  echo "  ${size}x${size} -> $(basename "$out")"
}

# render_opaque is for platforms that apply their own icon mask (iOS,
# macOS/Tauri, Android adaptive). Apple's App Store rejects icons with an
# alpha channel, so we flatten the master SVG's transparent rounded corners
# onto a solid amber background. The flattened pixels are invisible after
# the OS mask is applied, but they pass App Store Connect validation.
render_opaque() {
  local size="$1" src="$2" out="$3"
  rsvg-convert -w "$size" -h "$size" -b "#F5B800" "$src" -o "$out"
  # rsvg-convert -b sets the canvas background but still writes an alpha
  # channel. Re-encode to RGB-only (no alpha) so altool is happy.
  if command -v sips >/dev/null 2>&1; then
    sips -s format png -s formatOptions normal --deleteColorManagementProperties "$out" --out "$out" >/dev/null 2>&1
    sips -s hasAlpha no "$out" --out "$out" >/dev/null 2>&1 || true
  fi
  echo "  ${size}x${size} -> $(basename "$out") (opaque)"
}

# ─── iOS AppIcon set ───────────────────────────────────────────────────────
IOS_ICONSET="$WORKSPACE_ROOT/repos/mobile/ios/Beebeeb/Images.xcassets/AppIcon.appiconset"
if [ -d "$IOS_ICONSET" ]; then
  echo "iOS AppIcon set ($IOS_ICONSET):"
  render_opaque 40   "$MARK" "$IOS_ICONSET/AppIcon-20x20@2x.png"
  render_opaque 60   "$MARK" "$IOS_ICONSET/AppIcon-20x20@3x.png"
  render_opaque 29   "$MARK" "$IOS_ICONSET/AppIcon-29x29@1x.png"
  render_opaque 58   "$MARK" "$IOS_ICONSET/AppIcon-29x29@2x.png"
  render_opaque 87   "$MARK" "$IOS_ICONSET/AppIcon-29x29@3x.png"
  render_opaque 40   "$MARK" "$IOS_ICONSET/AppIcon-40x40@1x.png"
  render_opaque 80   "$MARK" "$IOS_ICONSET/AppIcon-40x40@2x.png"
  render_opaque 120  "$MARK" "$IOS_ICONSET/AppIcon-40x40@3x.png"
  render_opaque 120  "$MARK" "$IOS_ICONSET/AppIcon-60x60@2x.png"
  render_opaque 180  "$MARK" "$IOS_ICONSET/AppIcon-60x60@3x.png"
  render_opaque 76   "$MARK" "$IOS_ICONSET/AppIcon-76x76@1x.png"
  render_opaque 152  "$MARK" "$IOS_ICONSET/AppIcon-76x76@2x.png"
  render_opaque 167  "$MARK" "$IOS_ICONSET/AppIcon-83.5x83.5@2x.png"
  render_opaque 1024 "$MARK" "$IOS_ICONSET/App-Icon-1024x1024@1x.png"
else
  echo "skip: $IOS_ICONSET not present"
fi

# ─── mobile shared assets (used by expo for splash, adaptive icon, etc.) ──
MOBILE_ASSETS="$WORKSPACE_ROOT/repos/mobile/assets"
if [ -d "$MOBILE_ASSETS" ]; then
  echo "mobile assets ($MOBILE_ASSETS):"
  render_opaque 1024 "$MARK" "$MOBILE_ASSETS/icon.png"
  render_opaque 1024 "$MARK" "$MOBILE_ASSETS/adaptive-icon.png"
  # favicon used by web preview of mobile app
  if [ -f "$MOBILE_ASSETS/favicon.png" ]; then
    render 48 "$MARK" "$MOBILE_ASSETS/favicon.png"
  fi
else
  echo "skip: $MOBILE_ASSETS not present"
fi

# ─── web favicons ──────────────────────────────────────────────────────────
WEB_PUBLIC="$WORKSPACE_ROOT/repos/web/public"
if [ -d "$WEB_PUBLIC" ]; then
  echo "web favicons ($WEB_PUBLIC):"
  render 16  "$MARK" "$WEB_PUBLIC/favicon-16.png"
  render 32  "$MARK" "$WEB_PUBLIC/favicon-32.png"
  render 180 "$MARK" "$WEB_PUBLIC/apple-touch-icon.png"
  render 192 "$MARK" "$WEB_PUBLIC/icon-192.png"
  render 512 "$MARK" "$WEB_PUBLIC/icon-512.png"
else
  echo "skip: $WEB_PUBLIC not present"
fi

# ─── site (marketing) favicons + header logo ───────────────────────────────
SITE_PUBLIC="$WORKSPACE_ROOT/repos/site/public"
if [ -d "$SITE_PUBLIC" ]; then
  echo "site favicons + header logo ($SITE_PUBLIC):"
  render 16  "$MARK" "$SITE_PUBLIC/favicon-16.png"
  render 32  "$MARK" "$SITE_PUBLIC/favicon-32.png"
  render 180 "$MARK" "$SITE_PUBLIC/apple-touch-icon.png"
  render 192 "$MARK" "$SITE_PUBLIC/icon-192.png"
  render 512 "$MARK" "$SITE_PUBLIC/icon-512.png"
  if [ -d "$SITE_PUBLIC/assets" ]; then
    render 512 "$MARK" "$SITE_PUBLIC/assets/beebeeb-logo.png"
  fi
else
  echo "skip: $SITE_PUBLIC not present"
fi

# ─── desktop (Tauri) — both light and dark variants ────────────────────────
DESKTOP_ICONS="$WORKSPACE_ROOT/repos/desktop/src-tauri/icons"
if [ -d "$DESKTOP_ICONS" ]; then
  echo "desktop icons ($DESKTOP_ICONS):"
  render_opaque 32   "$MARK" "$DESKTOP_ICONS/32x32.png"
  render_opaque 128  "$MARK" "$DESKTOP_ICONS/128x128.png"
  render_opaque 256  "$MARK" "$DESKTOP_ICONS/128x128@2x.png"
  render_opaque 1024 "$MARK" "$DESKTOP_ICONS/icon.png"
else
  echo "skip: $DESKTOP_ICONS not present"
fi

# ─── android adaptive icon ─────────────────────────────────────────────────
ANDROID_RES="$WORKSPACE_ROOT/repos/mobile/android/app/src/main/res"
if [ -d "$ANDROID_RES" ]; then
  echo "android adaptive icon ($ANDROID_RES):"
  for d in mipmap-mdpi:48 mipmap-hdpi:72 mipmap-xhdpi:96 mipmap-xxhdpi:144 mipmap-xxxhdpi:192; do
    dir="${d%%:*}"; size="${d##*:}"
    if [ -d "$ANDROID_RES/$dir" ]; then
      render "$size" "$MARK" "$ANDROID_RES/$dir/ic_launcher.png"
      render "$size" "$MARK" "$ANDROID_RES/$dir/ic_launcher_round.png"
      render "$size" "$MARK" "$ANDROID_RES/$dir/ic_launcher_foreground.png"
    fi
  done
else
  echo "skip: $ANDROID_RES not present"
fi

echo
echo "done. commit the regenerated PNGs in each repo."
