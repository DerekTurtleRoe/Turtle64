"""Generates Turtle64's app icon (a simple stylized turtle shell) at
several PNG sizes, plus a combined multi-resolution .ico for Windows.

This is a one-off asset-generation script, not part of the build; the
generated files are committed to the repo so packaging (AppImage/.deb/
.rpm/Flatpak desktop files, Windows exe icon) doesn't need Pillow at
build time. Re-run with `python gen_icon.py` from this directory if the
design ever needs to change.
"""

import math
from pathlib import Path

from PIL import Image, ImageDraw

OUT_DIR = Path(__file__).parent
BG = (0x1C, 0x24, 0x20, 255)  # dark background matching the app's dark theme
SHELL = (0x3D, 0xB8, 0x6A, 255)  # "turtle green" accent used throughout the UI
SHELL_DARK = (0x2E, 0x8F, 0x52, 255)
SKIN = (0x8F, 0xD9, 0xB3, 255)


def draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    pad = size * 0.06
    d.rounded_rectangle([pad, pad, size - pad, size - pad], radius=size * 0.22, fill=BG)

    cx, cy = size / 2, size / 2 + size * 0.03
    shell_r = size * 0.33

    # Legs/head as simple rounded blobs peeking from under the shell.
    limb_r = size * 0.085
    for angle_deg in (35, 145, 215, 325):
        angle = math.radians(angle_deg)
        lx = cx + math.cos(angle) * shell_r * 0.92
        ly = cy + math.sin(angle) * shell_r * 0.92
        d.ellipse([lx - limb_r, ly - limb_r, lx + limb_r, ly + limb_r], fill=SKIN)
    head_r = size * 0.1
    hx, hy = cx, cy - shell_r * 1.05
    d.ellipse([hx - head_r, hy - head_r, hx + head_r, hy + head_r], fill=SKIN)

    # Shell body + simple hexagonal plate pattern.
    d.ellipse([cx - shell_r, cy - shell_r, cx + shell_r, cy + shell_r], fill=SHELL)
    d.ellipse(
        [cx - shell_r, cy - shell_r, cx + shell_r, cy + shell_r],
        outline=SHELL_DARK,
        width=max(1, int(size * 0.012)),
    )

    def hexagon(center, r):
        pts = []
        for i in range(6):
            a = math.radians(60 * i - 90)
            pts.append((center[0] + math.cos(a) * r, center[1] + math.sin(a) * r))
        return pts

    plate_r = shell_r * 0.32
    d.polygon(hexagon((cx, cy), plate_r), outline=SHELL_DARK, width=max(1, int(size * 0.01)))
    for angle_deg in (0, 60, 120, 180, 240, 300):
        angle = math.radians(angle_deg)
        px = cx + math.cos(angle) * plate_r * 1.9
        py = cy + math.sin(angle) * plate_r * 1.9
        d.polygon(hexagon((px, py), plate_r * 0.85), outline=SHELL_DARK, width=max(1, int(size * 0.01)))

    return img


def main() -> None:
    sizes = [16, 24, 32, 48, 64, 128, 256, 512]
    images = {s: draw_icon(s) for s in sizes}

    for s, img in images.items():
        img.save(OUT_DIR / f"turtle64_{s}.png")

    images[256].save(OUT_DIR / "turtle64.png")
    images[512].save(OUT_DIR / "turtle64_512.png")

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    images[256].save(
        OUT_DIR / "turtle64.ico",
        sizes=[(s, s) for s in ico_sizes],
    )

    # Raw RGBA8 bytes at a fixed size, for embedding directly as the eframe
    # window icon via `include_bytes!` without needing an image-decoding
    # crate as a runtime dependency.
    icon_rgba = images[256].convert("RGBA")
    (OUT_DIR / "turtle64_256.rgba").write_bytes(icon_rgba.tobytes())

    print("Wrote icons to", OUT_DIR)


if __name__ == "__main__":
    main()
