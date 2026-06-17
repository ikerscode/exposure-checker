#!/usr/bin/env python3
"""
Generate Gullwing icon assets from the master SVG definition.

Run from the repo root:
    python scripts/generate_icons.py

Outputs → exposure_checker/gui/assets/icons/
    gullwing-mark.svg      master SVG (512×512)
    icon-16.png  icon-32.png  icon-48.png  icon-128.png  icon-256.png  icon-512.png
    icon-header.png        40×40, transparent bg, gull paths only
    icon.ico               multi-size Windows icon (16/32/48/256)
    icon.icns              macOS bundle icon (macOS only via iconutil)
"""

import math
import os
import subprocess
import sys
from pathlib import Path

ROOT  = Path(__file__).resolve().parent.parent
ICONS = ROOT / "exposure_checker" / "gui" / "assets" / "icons"
ICONS.mkdir(parents=True, exist_ok=True)

GOLD     = "#F6A93B"
GOLD_RGB = (246, 169, 59)
BG_HEX   = "#0B0E16"
BG_RGB   = (11, 14, 22)

# Primary gull Bézier at 512-px coordinate space (spec coords)
_P0 = (220, 297)
_P1 = (238, 310)
_P2 = (248, 316)
_P3 = (256, 312)  # centre dip
_P4 = (270, 308)
_P5 = (352, 264)
_P6 = (420, 241)

# Secondary gull (flock motif) — two short strokes
_SEC = [
    ((354, 157), (362, 157), (370, 153), (374, 151)),  # left wing
    ((374, 151), (378, 149), (392, 145), (410, 141)),  # right wing
]

# Header icon: crop viewBox that frames the primary gull with comfortable padding
_HDR_VBOX = "190 225 250 140"  # x y w h  (roughly 2:1 ratio, will scale to square)


# ── SVG builders ───────────────────────────────────────────────────────────────

def _pts_to_path(*pts) -> str:
    """Build a cubic-Bézier SVG path from an even number of (x,y) tuples.
    First pair is the M command; subsequent groups of 3 form C commands."""
    coords = [f"{x:.1f},{y:.1f}" for x, y in pts]
    return f"M {coords[0]} C {' '.join(coords[1:])}"


def _scale(*pts, s: float):
    return tuple((x * s, y * s) for x, y in pts)


def master_svg(size: int = 512) -> str:
    k = size / 512.0
    rx = round(0.23 * size)
    gx, gy = size * 0.50, size * 0.666
    sw  = max(2, round(33 * k))
    sw2 = max(1, round(8  * k))

    p0, p1, p2, p3, p4, p5, p6 = _scale(
        _P0, _P1, _P2, _P3, _P4, _P5, _P6, s=k
    )

    sec_paths = []
    for seg in _SEC:
        a, b, c, d = _scale(*seg, s=k)
        sec_paths.append(
            f'  <path d="M {a[0]:.1f},{a[1]:.1f} '
            f'C {b[0]:.1f},{b[1]:.1f} {c[0]:.1f},{c[1]:.1f} {d[0]:.1f},{d[1]:.1f}" '
            f'stroke="{GOLD}" stroke-width="{sw2}" stroke-linecap="round" fill="none"/>'
        )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {size} {size}" width="{size}" height="{size}">\n'
        f'  <rect x="0" y="0" width="{size}" height="{size}" '
        f'rx="{rx}" ry="{rx}" fill="{BG_HEX}"/>\n'
        f'  <ellipse cx="{gx:.1f}" cy="{gy:.1f}" '
        f'rx="{size*0.39:.1f}" ry="{size*0.16:.1f}" fill="{GOLD}" opacity="0.10"/>\n'
        f'  <ellipse cx="{gx:.1f}" cy="{gy:.1f}" '
        f'rx="{size*0.27:.1f}" ry="{size*0.11:.1f}" fill="{GOLD}" opacity="0.16"/>\n'
        f'  <ellipse cx="{gx:.1f}" cy="{gy:.1f}" '
        f'rx="{size*0.16:.1f}" ry="{size*0.06:.1f}" fill="{GOLD}" opacity="0.22"/>\n'
        f'  <path d="M {p0[0]:.1f},{p0[1]:.1f} '
        f'C {p1[0]:.1f},{p1[1]:.1f} {p2[0]:.1f},{p2[1]:.1f} {p3[0]:.1f},{p3[1]:.1f} '
        f'C {p4[0]:.1f},{p4[1]:.1f} {p5[0]:.1f},{p5[1]:.1f} {p6[0]:.1f},{p6[1]:.1f}" '
        f'stroke="{GOLD}" stroke-width="{sw}" '
        f'stroke-linecap="round" stroke-linejoin="round" fill="none"/>\n'
        + "\n".join(sec_paths) + "\n"
        f"</svg>"
    )


def header_svg(size: int = 40) -> str:
    """Gull mark only — transparent background, cropped viewport."""
    vb_x, vb_y, vb_w, vb_h = (float(v) for v in _HDR_VBOX.split())
    stroke_output_px = max(2.0, size * 0.065)
    sw = round(stroke_output_px * vb_w / size)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="{_HDR_VBOX}" width="{size}" height="{size}">\n'
        f'  <path d="M {_P0[0]},{_P0[1]} '
        f'C {_P1[0]},{_P1[1]} {_P2[0]},{_P2[1]} {_P3[0]},{_P3[1]} '
        f'C {_P4[0]},{_P4[1]} {_P5[0]},{_P5[1]} {_P6[0]},{_P6[1]}" '
        f'stroke="{GOLD}" stroke-width="{sw}" '
        f'stroke-linecap="round" stroke-linejoin="round" fill="none"/>\n'
        f"</svg>"
    )


# ── Pillow helpers ─────────────────────────────────────────────────────────────

def _cubic_bezier(t: float, p0, p1, p2, p3):
    mt = 1 - t
    return (
        mt**3 * p0[0] + 3*mt**2*t * p1[0] + 3*mt*t**2 * p2[0] + t**3 * p3[0],
        mt**3 * p0[1] + 3*mt**2*t * p1[1] + 3*mt*t**2 * p2[1] + t**3 * p3[1],
    )


def _bezier_pts(p0, p1, p2, p3, n: int = 80):
    return [_cubic_bezier(i / n, p0, p1, p2, p3) for i in range(n + 1)]


def _draw_pil(size: int):
    from PIL import Image, ImageDraw

    k  = size / 512.0
    rx = round(0.23 * size)

    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background rounded rectangle
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=rx,
                            fill=(*BG_RGB, 255))

    # Sunset glow ellipses (alpha-composited)
    gx, gy = round(size * 0.50), round(size * 0.666)
    for rx_e, ry_e, alpha in [
        (round(size * 0.39), round(size * 0.16), round(0.10 * 255)),
        (round(size * 0.27), round(size * 0.11), round(0.16 * 255)),
        (round(size * 0.16), round(size * 0.06), round(0.22 * 255)),
    ]:
        glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        gd   = ImageDraw.Draw(glow)
        gd.ellipse([gx - rx_e, gy - ry_e, gx + rx_e, gy + ry_e],
                   fill=(*GOLD_RGB, alpha))
        img = Image.alpha_composite(img, glow)

    draw = ImageDraw.Draw(img)

    # Primary gull (two bezier segments)
    sw = max(2, round(33 * k))
    pts_a = _bezier_pts(
        (k * _P0[0], k * _P0[1]), (k * _P1[0], k * _P1[1]),
        (k * _P2[0], k * _P2[1]), (k * _P3[0], k * _P3[1]),
    )
    pts_b = _bezier_pts(
        (k * _P3[0], k * _P3[1]), (k * _P4[0], k * _P4[1]),
        (k * _P5[0], k * _P5[1]), (k * _P6[0], k * _P6[1]),
    )
    all_pts = [(round(x), round(y)) for x, y in pts_a + pts_b[1:]]
    for i in range(len(all_pts) - 1):
        draw.line([all_pts[i], all_pts[i + 1]],
                  fill=(*GOLD_RGB, 255), width=sw)

    # Secondary gull
    sw2 = max(1, round(8 * k))
    for seg in _SEC:
        s0, s1, s2, s3 = [(x * k, y * k) for x, y in seg]
        pts = [(round(x), round(y)) for x, y in _bezier_pts(s0, s1, s2, s3, n=30)]
        for i in range(len(pts) - 1):
            draw.line([pts[i], pts[i + 1]], fill=(*GOLD_RGB, 255), width=sw2)

    # Clip to rounded shape (removes any glow overflow at corners)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1],
                                           radius=rx, fill=255)
    img.putalpha(mask)
    return img


def _draw_header_pil(size: int = 40):
    """Gold gull on transparent background, cropped to the gull's bounding box."""
    from PIL import Image, ImageDraw

    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Map gull path from the header-crop coordinate space (vb 190,225 250×140)
    # to the output pixel space.
    vb_x, vb_y, vb_w, vb_h = 190.0, 225.0, 250.0, 140.0
    kx = size / vb_w
    ky = size / vb_h

    def _map(x, y):
        return ((x - vb_x) * kx, (y - vb_y) * ky)

    pts_a = [_map(*_cubic_bezier(i / 80, _P0, _P1, _P2, _P3)) for i in range(81)]
    pts_b = [_map(*_cubic_bezier(i / 80, _P3, _P4, _P5, _P6)) for i in range(81)]
    all_pts = [(round(x), round(y)) for x, y in pts_a + pts_b[1:]]

    sw = max(2, round(size * 0.065))
    for i in range(len(all_pts) - 1):
        draw.line([all_pts[i], all_pts[i + 1]],
                  fill=(*GOLD_RGB, 255), width=sw)

    return img


# ── Rasterization ──────────────────────────────────────────────────────────────

def _rasterize(svg_text: str, out_path: Path, width: int, height: int) -> bool:
    """Try cairosvg first; fall back to Pillow-based drawing if unavailable."""
    try:
        import cairosvg
        cairosvg.svg2png(
            bytestring=svg_text.encode(),
            write_to=str(out_path),
            output_width=width,
            output_height=height,
        )
        return True
    except ImportError:
        print("cairosvg not found — using Pillow fallback")
    except Exception as e:
        print(f"cairosvg failed ({e}) — using Pillow fallback")
    return False


# ── ICO / ICNS writers ─────────────────────────────────────────────────────────

def _write_ico(images: dict, path: Path):
    """Save a multi-resolution .ico.  `images` maps size → PIL Image."""
    from PIL import Image
    sizes = sorted(images.keys())
    base  = images[sizes[0]]
    rest  = [images[s] for s in sizes[1:]]
    base.save(
        str(path),
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=rest,
    )
    print(f"  wrote {path.name}")


def _write_icns(png_map: dict, path: Path):
    """Build a .icns using iconutil (macOS only). Skips on other platforms."""
    import platform
    if platform.system() != "Darwin":
        print("  skipping .icns — iconutil is macOS-only")
        return
    if not png_map:
        return

    import tempfile, shutil
    iconset = Path(tempfile.mkdtemp(suffix=".iconset"))
    try:
        from PIL import Image
        mapping = {
            16: "icon_16x16", 32: "icon_32x32", 64: "icon_64x64",
            128: "icon_128x128", 256: "icon_256x256", 512: "icon_512x512",
        }
        for size, name in mapping.items():
            img = png_map.get(size)
            if img is None:
                continue
            img.save(str(iconset / f"{name}.png"))
            if size * 2 in png_map:
                png_map[size * 2].save(str(iconset / f"{name}@2x.png"))
        result = subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(path)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"  wrote {path.name}")
        else:
            print(f"  iconutil failed: {result.stderr.strip()}")
    finally:
        shutil.rmtree(str(iconset), ignore_errors=True)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    try:
        from PIL import Image
        HAS_PIL = True
    except ImportError:
        HAS_PIL = False
        print("ERROR: Pillow is required.  pip install pillow")
        sys.exit(1)

    # 1. Write master SVG
    svg_text = master_svg(512)
    svg_path = ICONS / "gullwing-mark.svg"
    svg_path.write_text(svg_text, encoding="utf-8")
    print(f"  wrote {svg_path.name}")

    # 2. Write header SVG
    hdr_svg_text = header_svg(40)
    (ICONS / "gullwing-header.svg").write_text(hdr_svg_text, encoding="utf-8")

    # 3. Rasterize main icon at each size
    SIZES      = [16, 32, 48, 128, 256, 512]
    pil_images = {}  # size → PIL Image

    for sz in SIZES:
        out = ICONS / f"icon-{sz}.png"
        svg_for_size = master_svg(sz)
        ok = _rasterize(svg_for_size, out, sz, sz)
        if ok:
            img = Image.open(str(out)).convert("RGBA")
        else:
            print(f"  drawing {sz}×{sz} with Pillow…")
            img = _draw_pil(sz)
            img.save(str(out))
        pil_images[sz] = img
        print(f"  wrote icon-{sz}.png")

    # 4. Header icon (40×40, transparent bg)
    hdr_out  = ICONS / "icon-header.png"
    hdr_svg  = header_svg(40)
    ok = _rasterize(hdr_svg, hdr_out, 40, 40)
    if ok:
        pass  # cairosvg wrote it
    else:
        hdr_img = _draw_header_pil(40)
        hdr_img.save(str(hdr_out))
    print(f"  wrote icon-header.png")

    # 5. .ico
    ico_sizes = {s: pil_images[s] for s in [16, 32, 48, 256] if s in pil_images}
    if ico_sizes:
        _write_ico(ico_sizes, ICONS / "icon.ico")

    # 6. .icns (macOS only)
    _write_icns(pil_images, ICONS / "icon.icns")

    print(f"\nAll assets written to {ICONS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
