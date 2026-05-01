# Beebeeb Brand Assets

Single source of truth for the Beebeeb visual identity. All platform repos (web, mobile, desktop, site) should reference or copy from here.

## Assets

### Mark (app icon, favicon, social)
- `logo-mark.svg` — amber square, dark "b" (default, for light backgrounds)
- `logo-mark-dark.svg` — dark square, amber "b" (for dark backgrounds, splash screens)

### Wordmark (headers, navigation)
- `logo-wordmark.svg` — "beebeeb.io" on light backgrounds (ink text, amber ".io")
- `logo-wordmark-light.svg` — "beebeeb.io" on dark backgrounds (paper text, amber ".io")

### Full logo (mark + wordmark)
- `logo-full.svg` — mark and wordmark side by side

## Brand colors

| Token | Value | Use |
|-------|-------|-----|
| Amber | `#F5B800` / `oklch(0.82 0.17 84)` | THE accent. Encryption state, primary CTAs only. |
| Ink | `#1A1714` / `oklch(0.18 0.01 70)` | Dark text, mark background |
| Paper | `#FAF8F5` / `oklch(0.985 0.004 85)` | Light backgrounds |

## Typography

- **Sans:** Inter (humans read this)
- **Mono:** JetBrains Mono (machines read this — hashes, IDs, sizes, timestamps)
- Rule: "If you can't read it aloud, it's mono."

## Rules

- Amber is the ONLY accent color. No secondary brand color exists by design.
- No emojis in product UI.
- No flag emojis for EU references (exception: data residency region selector, approved by founder).
- Voice: honest over reassuring. "We can't recover this." not "bank-grade security."
- All-lowercase always for the wordmark.
- Minimum mark size: 14px.
- Minimum clear space around mark: 1x the mark width.

## Platform usage

| Platform | Mark | Wordmark |
|----------|------|----------|
| iOS app icon | `logo-mark.svg` exported at 1024x1024 | — |
| Android adaptive icon | `logo-mark.svg` foreground on `#FAF8F5` | — |
| Web favicon | `logo-mark.svg` exported at 32x32 | — |
| Web sidebar | — | `logo-wordmark.svg` inline as component |
| Marketing site header | `logo-full.svg` | — |
| Email header | `logo-full.svg` exported at 2x PNG | — |
| Share Extension icon | `logo-mark.svg` at 60x60 | — |
| File Provider icon | `logo-mark.svg` at 60x60 | — |
