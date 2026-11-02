#!/usr/bin/env python3
"""Generates brand/products/{product}-{light,dark}.svg and {product}-full-{light,dark}.svg.

Every product keeps the Beebeeb "b" on the tile and adds its glyph on a round badge, bottom right
(option A, Guus 2026-11-02, task 2322). One pattern, no per-product colour. The full logo is that icon,
the unchanged "beebeeb.io" wordmark and the product name underneath it as a label (option 3, same day).
The main Beebeeb logo (../logo-mark.svg, ../logo-full.svg) is not touched.

    python3 brand/products/build.py           # write the 20 SVGs
    python3 brand/products/build.py --check   # exit 1 if a file on disk differs from the generator
"""
import re
import sys
from enum import Enum
from pathlib import Path

PRODUCTS_DIR = Path(__file__).resolve().parent
LOGO_MARK = PRODUCTS_DIR.parent / "logo-mark.svg"

AMBER = "#F5B800"
INK = "#1A1714"
PAPER = "#FAF8F5"  # the wordmark on a dark surface, as in ../logo-wordmark-light.svg
INK_2 = "#57534e"
INK_2_DARK = "#a8a29e"

TILE_SIZE = 512
TILE_RADIUS = 102  # the same 102/512 corner as logo-mark.svg

# The "b" is the glyph path of logo-mark.svg at its scale, moved up and left (from 150.8, 382.7) to
# free the lower right corner for the badge. One decimal, as in the approved reference render.
B_SCALE = 0.1723
B_ORIGIN = (116.8, 360.7)

BADGE_CENTER = 378
BADGE_RING_RADIUS = 104  # the cut-out ring in the tile colour, which keeps the badge apart from the b
BADGE_DISC_RADIUS = 88

GLYPH_SIZE = 104  # tile units: the 24-grid glyph is scaled to this
GLYPH_GRID = 24
GLYPH_STROKE = 13  # tile units; 3 on the 24 grid, heavier than the in-app 1.6 so it holds at 29 px

# The full logo sits on the 800 x 100 canvas of ../logo-full.svg, with the icon at the same size and
# place. The other sizes keep the proportions of the approved reference render (icon 52, gap 14,
# wordmark 34, label 12, gap 4), so each is a fraction of the icon.
FULL_CANVAS = (800, 100)
FULL_ICON_SIZE = 88
FULL_ICON_Y = 6
ICON_TO_TEXT_GAP = 14 / 52
WORDMARK_SIZE = 34 / 52
WORDMARK_TRACKING = -2 / 72  # em; logo-full.svg letter-spacing -2 at font-size 72
LABEL_SIZE = 12 / 52
LABEL_TRACKING = 0.18  # em
LABEL_GAP = 4 / 52
# Vertical font metrics (em) to place baselines in SVG, where there is no line box: Inter's ascent and
# descent, and JetBrains Mono's, whose line box is its ascent plus descent.
INTER_ASCENT, INTER_DESCENT = 0.96875, 0.2412
MONO_ASCENT, MONO_DESCENT = 1.02, 0.3

# 24-grid stroke glyphs: Drive, Pass and Mail are the shipped icon set (folder, key, mail); VPN and
# Chat are new. The shield is NOT used for VPN: it is reserved for encryption state.
GLYPHS = {
    "drive": "M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z",
    "pass": "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
    "vpn": "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9M12 3c-2.5 2.6-3.8 5.6-3.8 9s1.3 6.4 3.8 9",
    "mail": "M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2zM22 6l-10 7L2 6",
    "chat": "M21 11.5a8.4 8.4 0 0 1-12.3 7.4L3 21l2.1-5.6A8.4 8.4 0 1 1 21 11.5z",
}


DISPLAY_NAMES = {"drive": "Drive", "pass": "Pass", "vpn": "VPN", "mail": "Mail", "chat": "Chat"}


class Tone(Enum):
    LIGHT = "light"
    DARK = "dark"

    @property
    def tile(self) -> str:
        return AMBER if self is Tone.LIGHT else INK

    @property
    def ink(self) -> str:
        return INK if self is Tone.LIGHT else AMBER

    @property
    def wordmark(self) -> str:
        return INK if self is Tone.LIGHT else PAPER

    @property
    def label(self) -> str:
        return INK_2 if self is Tone.LIGHT else INK_2_DARK


def b_glyph_path() -> str:
    """The Inter Bold "b" outline, read from logo-mark.svg so the two can never drift apart."""
    paths = re.findall(r'<path d="([^"]+)"', LOGO_MARK.read_text())
    if len(paths) != 1:
        raise SystemExit(f"{LOGO_MARK}: expected exactly one <path>, found {len(paths)}")
    return paths[0]


def format_number(value: float) -> str:
    return f"{value:.4f}".rstrip("0").rstrip(".")


def icon_elements(product: str, tone: Tone) -> list[str]:
    scale = GLYPH_SIZE / GLYPH_GRID
    glyph_origin = BADGE_CENTER - GLYPH_SIZE / 2
    b_x, b_y = B_ORIGIN
    return [
        f'<rect width="{TILE_SIZE}" height="{TILE_SIZE}" rx="{TILE_RADIUS}" fill="{tone.tile}"/>',
        f'<g fill="{tone.ink}" transform="translate({format_number(b_x)} {format_number(b_y)}) scale({B_SCALE:.6f} -{B_SCALE:.6f})">',
        f'  <path d="{b_glyph_path()}"/>',
        "</g>",
        f'<circle cx="{BADGE_CENTER}" cy="{BADGE_CENTER}" r="{BADGE_RING_RADIUS}" fill="{tone.tile}"/>',
        f'<circle cx="{BADGE_CENTER}" cy="{BADGE_CENTER}" r="{BADGE_DISC_RADIUS}" fill="{tone.ink}"/>',
        f'<g transform="translate({format_number(glyph_origin)} {format_number(glyph_origin)}) scale({format_number(scale)})" stroke="{tone.tile}" stroke-width="{format_number(GLYPH_STROKE / scale)}" stroke-linecap="round" stroke-linejoin="round">',
        f'  <path d="{GLYPHS[product]}"/>',
        "</g>",
    ]


def indent(lines: list[str], spaces: int) -> str:
    return "\n".join(" " * spaces + line for line in lines)


def product_icon(product: str, tone: Tone) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {TILE_SIZE} {TILE_SIZE}" fill="none">
  <!-- Beebeeb {DISPLAY_NAMES[product]} icon, {tone.value}: the b plus the {product} glyph on a round badge.
       Generated by brand/products/build.py; edit the generator, not this file. -->
{indent(icon_elements(product, tone), 2)}
</svg>
"""


def product_full_logo(product: str, tone: Tone) -> str:
    wordmark_size = FULL_ICON_SIZE * WORDMARK_SIZE
    label_size = FULL_ICON_SIZE * LABEL_SIZE
    label_gap = FULL_ICON_SIZE * LABEL_GAP
    text_x = FULL_ICON_SIZE + FULL_ICON_SIZE * ICON_TO_TEXT_GAP
    # The text block is centred on the icon: a one-line wordmark box, the gap, then the label's line box.
    block_height = wordmark_size + label_gap + label_size * (MONO_ASCENT + MONO_DESCENT)
    block_top = FULL_ICON_Y + FULL_ICON_SIZE / 2 - block_height / 2
    wordmark_baseline = block_top + wordmark_size * (INTER_ASCENT + (1 - INTER_ASCENT - INTER_DESCENT) / 2)
    label_baseline = block_top + wordmark_size + label_gap + label_size * MONO_ASCENT
    canvas_width, canvas_height = FULL_CANVAS
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {canvas_width} {canvas_height}" fill="none">
  <!-- Beebeeb {DISPLAY_NAMES[product]} full logo, {tone.value}: the product icon, the beebeeb.io wordmark, the product name under it.
       Generated by brand/products/build.py; edit the generator, not this file. -->
  <g transform="translate(0 {FULL_ICON_Y}) scale({FULL_ICON_SIZE / TILE_SIZE:.6f})">
{indent(icon_elements(product, tone), 4)}
  </g>
  <text x="{format_number(text_x)}" y="{format_number(wordmark_baseline)}"
        font-family="Inter, ui-sans-serif, system-ui, sans-serif"
        font-size="{format_number(wordmark_size)}" font-weight="700" letter-spacing="{format_number(wordmark_size * WORDMARK_TRACKING)}">
    <tspan fill="{tone.wordmark}">beebeeb</tspan><tspan fill="{AMBER}">.io</tspan>
  </text>
  <text x="{format_number(text_x)}" y="{format_number(label_baseline)}"
        font-family="'JetBrains Mono', ui-monospace, monospace"
        font-size="{format_number(label_size)}" font-weight="500" letter-spacing="{format_number(label_size * LABEL_TRACKING)}" fill="{tone.label}">{DISPLAY_NAMES[product].upper()}</text>
</svg>
"""


def expected_files() -> dict[Path, str]:
    files = {}
    for product in GLYPHS:
        for tone in Tone:
            files[PRODUCTS_DIR / f"{product}-{tone.value}.svg"] = product_icon(product, tone)
            files[PRODUCTS_DIR / f"{product}-full-{tone.value}.svg"] = product_full_logo(product, tone)
    return files


def main() -> int:
    files = expected_files()
    if "--check" in sys.argv[1:]:
        drifted = [path.name for path, svg in files.items() if not path.exists() or path.read_text() != svg]
        for name in drifted:
            print(f"drift: {name}")
        print(f"{len(files) - len(drifted)} of {len(files)} SVGs match the generator")
        return 1 if drifted else 0
    for path, svg in files.items():
        path.write_text(svg)
    print(f"wrote {len(files)} SVGs to {PRODUCTS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
