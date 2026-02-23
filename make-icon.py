#!/usr/bin/env python3
"""
Generate OpenClaw Security Monitor app icon using pure Python stdlib.
Outputs an iconset directory then calls iconutil to produce the .icns file.

Design: dark navy shield with blue border and three orange claw marks.
"""

import math
import os
import struct
import subprocess
import sys
import zlib

# ---------------------------------------------------------------------------
# Raw PNG writer (no dependencies)
# ---------------------------------------------------------------------------

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)


def make_png(width: int, height: int, pixels: bytearray) -> bytes:
    """
    pixels: flat RGBA bytearray, row-major (4 bytes per pixel).
    """
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))

    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw += b"\x00"  # filter: None
        raw += pixels[y * stride : (y + 1) * stride]

    idat = _png_chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


# ---------------------------------------------------------------------------
# Shield geometry
# ---------------------------------------------------------------------------

def _point_in_shield(nx: float, ny: float) -> bool:
    """
    Normalised coordinates (0-1). Classic heraldic shield:
    - rectangular top section down to ~62 % height
    - triangular bottom pointing at (0.5, 0.93)
    Rounded top corners with radius ~10 %.
    """
    PAD = 0.10
    left, right, top = PAD, 1.0 - PAD, PAD
    w = right - left
    mid_y = top + 0.58 * (1.0 - 2 * PAD)
    bot_y = 0.93

    if nx < left or nx > right or ny < top or ny > bot_y:
        return False

    if ny <= mid_y:
        # Rounded top-left corner
        rl, rt = left + 0.12 * w, top + 0.09 * w
        if nx < rl and ny < rt:
            d = math.hypot(nx - rl, ny - rt)
            return d <= 0.12 * w
        # Rounded top-right corner
        rr = right - 0.12 * w
        if nx > rr and ny < rt:
            d = math.hypot(nx - rr, ny - rt)
            return d <= 0.12 * w
        return True
    else:
        # Triangular bottom
        t = (ny - mid_y) / (bot_y - mid_y)
        cl = left + t * (0.5 - left)
        cr = right - t * (right - 0.5)
        return cl <= nx <= cr


def _border_alpha(nx: float, ny: float, bw: float = 0.038) -> float:
    """
    Returns a 0-1 value for how much "border" colour to apply.
    Uses finite differences to detect the edge of the shield.
    """
    inside = _point_in_shield(nx, ny)
    if not inside:
        return 0.0
    # Sample neighbours at bw distance
    neighbors = [
        _point_in_shield(nx - bw, ny),
        _point_in_shield(nx + bw, ny),
        _point_in_shield(nx, ny - bw),
        _point_in_shield(nx, ny + bw),
        _point_in_shield(nx - bw * 0.7, ny - bw * 0.7),
        _point_in_shield(nx + bw * 0.7, ny - bw * 0.7),
        _point_in_shield(nx - bw * 0.7, ny + bw * 0.7),
        _point_in_shield(nx + bw * 0.7, ny + bw * 0.7),
    ]
    edge_fraction = neighbors.count(False) / len(neighbors)
    return min(1.0, edge_fraction * 2.5)


def _claw_alpha(nx: float, ny: float, lw: float) -> float:
    """
    Three diagonal parallel claw scratches.
    Returns 0-1 coverage (anti-aliased by soft-edge distance).
    """
    cx, cy = 0.5, 0.50
    offsets = [-0.085, 0.0, 0.085]
    best = 0.0
    for off in offsets:
        x1, y1 = cx - 0.16 + off * 0.6, cy - 0.22
        x2, y2 = cx + 0.16 + off * 0.6, cy + 0.22
        dx, dy = x2 - x1, y2 - y1
        len_sq = dx * dx + dy * dy
        t = max(0.0, min(1.0, ((nx - x1) * dx + (ny - y1) * dy) / len_sq))
        px, py = x1 + t * dx, y1 + t * dy
        dist = math.hypot(nx - px, ny - py)
        # Soft edge
        coverage = max(0.0, 1.0 - dist / lw)
        best = max(best, coverage)
    return best


# ---------------------------------------------------------------------------
# Icon renderer
# ---------------------------------------------------------------------------

def render_icon(size: int) -> bytearray:
    s = size
    pixels = bytearray(s * s * 4)

    # Colours
    NAVY1  = (15,  28,  58)   # top of shield body
    NAVY2  = (10,  18,  42)   # bottom of shield body
    BORD1  = (55, 140, 255)   # border top
    BORD2  = (30,  90, 200)   # border bottom
    CLAW   = (255, 120,  30)  # claw marks
    CLAW_H = (255, 200, 100)  # claw highlight centre

    lw = max(0.018, 0.025 * (512 / s))   # claw line half-width (scale with size)
    bw = max(0.030, 0.038 * (512 / s))   # border width

    for y in range(s):
        ny = (y + 0.5) / s
        for x in range(s):
            nx = (x + 0.5) / s
            idx = (y * s + x) * 4

            if not _point_in_shield(nx, ny):
                # Transparent outside
                pixels[idx:idx+4] = b"\x00\x00\x00\x00"
                continue

            # Vertical gradient (0 = top, 1 = bottom)
            t = ny

            # Body colour
            r = int(NAVY1[0] + t * (NAVY2[0] - NAVY1[0]))
            g = int(NAVY1[1] + t * (NAVY2[1] - NAVY1[1]))
            b_col = int(NAVY1[2] + t * (NAVY2[2] - NAVY1[2]))

            # Border blend
            ba = _border_alpha(nx, ny, bw)
            if ba > 0:
                br = int(BORD1[0] + t * (BORD2[0] - BORD1[0]))
                bg = int(BORD1[1] + t * (BORD2[1] - BORD1[1]))
                bb = int(BORD1[2] + t * (BORD2[2] - BORD1[2]))
                r = int(r * (1 - ba) + br * ba)
                g = int(g * (1 - ba) + bg * ba)
                b_col = int(b_col * (1 - ba) + bb * ba)

            # Claw marks
            ca = _claw_alpha(nx, ny, lw)
            if ca > 0:
                # Mix claw colour; highlight towards centre
                mix = ca
                cr = int(CLAW[0] + ca * (CLAW_H[0] - CLAW[0]))
                cg = int(CLAW[1] + ca * (CLAW_H[1] - CLAW[1]))
                cb = int(CLAW[2] + ca * (CLAW_H[2] - CLAW[2]))
                r = int(r * (1 - mix) + cr * mix)
                g = int(g * (1 - mix) + cg * mix)
                b_col = int(b_col * (1 - mix) + cb * mix)

            pixels[idx]   = max(0, min(255, r))
            pixels[idx+1] = max(0, min(255, g))
            pixels[idx+2] = max(0, min(255, b_col))
            pixels[idx+3] = 255

    return pixels


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ICON_SIZES = [
    ("icon_16x16",     16),
    ("icon_16x16@2x",  32),
    ("icon_32x32",     32),
    ("icon_32x32@2x",  64),
    ("icon_128x128",  128),
    ("icon_128x128@2x", 256),
    ("icon_256x256",  256),
    ("icon_256x256@2x", 512),
    ("icon_512x512",  512),
    ("icon_512x512@2x", 1024),
]

def main():
    out_dir = os.path.join(os.path.dirname(__file__), "openclaw.iconset")
    os.makedirs(out_dir, exist_ok=True)

    rendered: dict[int, bytearray] = {}

    unique_sizes = sorted({s for _, s in ICON_SIZES})
    for size in unique_sizes:
        print(f"  Rendering {size}x{size}…", flush=True)
        rendered[size] = render_icon(size)

    for name, size in ICON_SIZES:
        path = os.path.join(out_dir, f"{name}.png")
        png_bytes = make_png(size, size, rendered[size])
        with open(path, "wb") as f:
            f.write(png_bytes)
        print(f"  Wrote {path}")

    icns_path = os.path.join(os.path.dirname(__file__), "openclaw.icns")
    print(f"\n  Running iconutil…")
    subprocess.run(
        ["iconutil", "-c", "icns", out_dir, "-o", icns_path],
        check=True,
    )
    print(f"  Created {icns_path}")
    return icns_path


if __name__ == "__main__":
    path = main()
    print(f"\nDone: {path}")
