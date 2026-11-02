# Beebeeb product icons

Drive, Pass, VPN, Mail and Chat share ONE icon pattern (Guus, 2026-11-02, task 2322): the Beebeeb "b" on the tile, plus the product's glyph on a round badge, bottom right. A product is told apart by its glyph and its name, never by colour.

![The ten icons at 512, 96 and 29 px](preview.png)

| Tone | Tile | b | Badge | Glyph |
|------|------|---|-------|-------|
| `-light` | Amber `#F5B800` | ink `#1A1714` | ink | Amber |
| `-dark` | ink `#1A1714` | Amber | Amber | ink |

The tile is 512 x 512 with `rx` 102, the same as `../logo-mark.svg`, and the "b" is that file's Inter Bold glyph path (read from it by the generator, never live text).

## Glyphs

| Product | Glyph | Files |
|---------|-------|-------|
| Drive | folder | `drive-light.svg`, `drive-dark.svg` |
| Pass | key | `pass-light.svg`, `pass-dark.svg` |
| VPN | globe | `vpn-light.svg`, `vpn-dark.svg` |
| Mail | envelope | `mail-light.svg`, `mail-dark.svg` |
| Chat | speech bubble | `chat-light.svg`, `chat-dark.svg` |

**The shield is reserved for encryption state.** VPN uses a globe so the shield keeps meaning "encrypted" everywhere it appears. Never use it as a product glyph.

## Regenerating

The SVGs are generated; edit `build.py`, not the files.

```sh
python3 brand/products/build.py           # write the 10 SVGs
python3 brand/products/build.py --check   # exit 1 if a file differs from the generator
```

`preview.png` is a render of these SVGs at the time they were last generated.

## Status

These are assets only. No shipped app icon (iOS, macOS, desktop, Android, favicon, site) uses them: Drive keeps shipping the plain "b" from `../logo-mark.svg` until Guus decides otherwise. The web components that draw the same icons are `BBProductIcon` and `BBProductLockup` in `@beebeeb/shared`.
