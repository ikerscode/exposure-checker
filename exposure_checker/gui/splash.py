#!/usr/bin/env python3
"""
Gullwing splash screen — cinematic raster renderer (pygame + numpy).

A photoreal-leaning Venice-canal sunset rendered entirely procedurally:

  • One-point-perspective canal with palazzo facades, limestone waterlines,
    striped mooring poles and moored gondolas, receding to a vanishing point.
  • The sun sets exactly at the vanishing point with a soft halo, volumetric
    god-rays and a multi-element lens flare.
  • Layered sunset-lit clouds with warm underbellies.
  • A real rippled water reflection of the entire scene (sky, sun, buildings,
    clouds AND the gulls) computed per-pixel with numpy — Fresnel fade, water
    tint, and sun-glitter sparkles.
  • A flock of seagulls glides prominently down the canal, with soft shadows
    and motion-blur ghosting.
  • Filmic (ACES) tone-mapping, bloom, vignette, subtle chromatic aberration
    and film grain for a photographic finish — then 2× supersampled downscale.

Everything is local: no network, no files, no subprocesses — pure rendering.

``run_splash()`` is blocking and self-contained. If pygame (or anything else)
is unavailable it returns False so the caller can fall back to the Tk splash.
numpy is optional: without it the renderer drops the per-pixel water/grade and
uses a lighter mirror reflection instead, so it still runs and still looks good.
"""

import math
import os
import random

os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")
os.environ.setdefault("SDL_VIDEO_CENTERED", "1")


def run_splash(duration: float = 7.0, version: str = "") -> bool:
    """Show the cinematic splash (blocking). Returns True if it ran, else False."""
    try:
        import pygame
        from pygame import gfxdraw  # noqa: F401
    except Exception:
        return False
    try:
        import numpy as _np
        have_np = True
    except Exception:
        _np = None
        have_np = False
    try:
        return _run(pygame, gfxdraw, _np, have_np, duration, version)
    except Exception:
        try:
            pygame.quit()
        except Exception:
            pass
        return False


# ── Colour helpers ──────────────────────────────────────────────────────────────

def _clamp(v, lo=0, hi=255):
    return max(lo, min(hi, int(v)))


def _lerp_col(c0, c1, t):
    return (
        _clamp(c0[0] + (c1[0] - c0[0]) * t),
        _clamp(c0[1] + (c1[1] - c0[1]) * t),
        _clamp(c0[2] + (c1[2] - c0[2]) * t),
    )


def _shade(c, k):
    return (_clamp(c[0] * k), _clamp(c[1] * k), _clamp(c[2] * k))


def _silhouette(c, fog):
    """Backlit facade: blend the plaster colour toward a cool shadow and dim it.

    With the sun setting at the end of the canal the buildings face away from the
    light, so they read as dark, slightly warm silhouettes with glowing windows —
    the dramatic 'contre-jour' look of real sunset-canal photography.
    """
    sh = (24, 20, 34)
    k = 0.60
    mixed = (c[0] * (1 - k) + sh[0] * k,
             c[1] * (1 - k) + sh[1] * k,
             c[2] * (1 - k) + sh[2] * k)
    return _shade(mixed, max(0.32, fog * 0.7))


# Sunset gradient (zenith → horizon)
_SKY = [
    (0.00, (8, 12, 44)),
    (0.20, (22, 20, 86)),
    (0.40, (66, 28, 92)),
    (0.57, (130, 40, 70)),
    (0.71, (196, 64, 50)),
    (0.83, (226, 100, 36)),
    (0.92, (244, 150, 54)),
    (1.00, (255, 198, 96)),
]


def _sky_color(frac):
    for i in range(len(_SKY) - 1):
        y0, c0 = _SKY[i]
        y1, c1 = _SKY[i + 1]
        if y0 <= frac <= y1:
            t = (frac - y0) / (y1 - y0) if y1 > y0 else 0.0
            return _lerp_col(c0, c1, t)
    return _SKY[-1][1]


# ── Main render routine ─────────────────────────────────────────────────────────

def _run(pygame, gfxdraw, np, have_np, duration, version):
    pygame.init()
    try:
        pygame.display.set_caption("Gullwing")
    except Exception:
        pass

    BASE_W, BASE_H = 760, 460
    SS = 2                       # supersample factor for geometry/bloom
    W, H = BASE_W * SS, BASE_H * SS
    HZ = int(H * 0.52)           # horizon line (supersampled space)
    HZ_w = HZ // SS              # horizon line at window resolution

    screen = pygame.display.set_mode((BASE_W, BASE_H), pygame.NOFRAME)
    scene = pygame.Surface((W, H)).convert()
    glow = pygame.Surface((W, H), pygame.SRCALPHA)

    rng = random.Random(7)

    # ── Cached static sky + stars ─────────────────────────────────────────────
    sky = pygame.Surface((W, H)).convert()
    for y in range(HZ):
        pygame.draw.line(sky, _sky_color(y / HZ), (0, y), (W, y))
    pygame.draw.rect(sky, (8, 26, 42), (0, HZ, W, H - HZ))
    star_pts = []
    for _ in range(140):
        sx = rng.randint(0, W - 1)
        sy = rng.randint(0, int(HZ * 0.55))
        b = rng.randint(140, 235)
        star_pts.append((sx, sy, b, rng.uniform(0, 6.28)))

    # ── Clouds (procedural, sunset-lit) ───────────────────────────────────────
    clouds = []
    for _ in range(7):
        cy = rng.randint(int(H * 0.10), int(HZ * 0.82))
        clouds.append({
            "x": rng.uniform(0, W),
            "y": cy,
            "w": rng.uniform(120 * SS, 300 * SS),
            "h": rng.uniform(20 * SS, 46 * SS),
            "spd": rng.uniform(3 * SS, 9 * SS),
            "puffs": rng.randint(4, 7),
            "seed": rng.random() * 999,
        })

    # ── Venice canal geometry (one-point perspective) ─────────────────────────
    F = 250.0 * SS
    CW = 3.1                # wider canal — less claustrophobic "tunnel" feel
    CAM_H = 1.4
    NEAR = 1.0
    FAR = 32.0
    SPEED = 2.7
    SUN_FRAC = 0.40         # horizontal sun position (0=left, 1=right)

    def proj(x, y, z):
        s = F / z
        return W / 2 + x * s, HZ - (y - CAM_H) * s, s

    _FACADE = [(202, 112, 58), (214, 146, 64), (190, 88, 56), (200, 152, 40),
               (202, 104, 88), (168, 96, 48), (210, 162, 56), (184, 104, 72),
               (206, 130, 96), (176, 120, 92)]
    _STONE = (202, 186, 146)
    _POLES = [((26, 58, 138), (238, 238, 246)),
              ((192, 48, 32), (238, 238, 246)),
              ((26, 58, 138), (192, 48, 32)),
              ((36, 96, 32), (240, 208, 48))]

    def _gen_seg(z0):
        return {
            "z0": z0, "len": rng.uniform(2.5, 4.0),
            "lh": rng.uniform(3.4, 5.4), "rh": rng.uniform(3.4, 5.4),
            "lc": rng.choice(_FACADE), "rc": rng.choice(_FACADE),
            "lrows": rng.randint(2, 4), "rrows": rng.randint(2, 4),
            "lcols": rng.randint(3, 5), "rcols": rng.randint(3, 5),
            "pole": rng.random() < 0.62, "pside": rng.choice((-1, 1)),
            "pcol": rng.choice(_POLES),
            "gond": rng.random() < 0.24, "gside": rng.choice((-1, 1)),
            "lwin": rng.random() < 0.9, "rwin": rng.random() < 0.9,
        }

    segments = []
    _z = NEAR
    while _z < FAR + 6:
        s = _gen_seg(_z)
        segments.append(s)
        _z += s["len"]

    # ── Embers / dust motes ───────────────────────────────────────────────────
    embers = []
    for _ in range(54):
        embers.append({
            "x": rng.uniform(0, W), "y": rng.uniform(0, H),
            "vy": rng.uniform(5 * SS, 18 * SS),
            "drift": rng.uniform(-6 * SS, 6 * SS),
            "r": rng.uniform(1.0 * SS, 2.6 * SS),
            "ph": rng.uniform(0, 6.28), "warm": rng.random() < 0.72,
        })

    # ── Fonts ─────────────────────────────────────────────────────────────────
    def _font(size, bold=True):
        for name in ("Helvetica Neue", "Helvetica", "Arial",
                     "DejaVu Sans", "Liberation Sans"):
            try:
                if pygame.font.match_font(name, bold=bold):
                    return pygame.font.SysFont(name, size, bold=bold)
            except Exception:
                continue
        return pygame.font.Font(None, size)

    # Titles render on the window surface (not the supersampled scene), so they
    # must be window-scale, NOT multiplied by SS.
    f_title = _font(32, bold=True)
    f_sub = _font(13, bold=False)
    f_small = _font(10, bold=False)

    stages = [
        (0.00, "Detecting platform and loading base configuration…"),
        (0.10, "Indexing port-risk database — 1 024 known services…"),
        (0.22, "Locating cron, launchd, and Task Scheduler entries…"),
        (0.35, "Compiling kernel-hardening rule-set — 34 sysctl checks…"),
        (0.47, "Mapping SUID/SGID binary search paths…"),
        (0.58, "Registering GPU, power, and NIC probe routines…"),
        (0.70, "Loading 90+ performance & security checks…"),
        (0.82, "Building protection-hardening baseline…"),
        (0.92, "All systems ready — launching Gullwing…"),
    ]

    # ── Bloom (threshold + multi-scale blur, additive) ────────────────────────
    def _bloom(src):
        w, h = src.get_size()
        s1 = pygame.transform.smoothscale(src, (max(1, w // 4), max(1, h // 4)))
        s2 = pygame.transform.smoothscale(s1, (max(1, w // 10), max(1, h // 10)))
        b1 = pygame.transform.smoothscale(s1, (w, h))
        b2 = pygame.transform.smoothscale(s2, (w, h))
        b1.blit(b2, (0, 0), special_flags=pygame.BLEND_RGBA_ADD)
        return b1

    # ── Gull (body, wings, dark tips, head, tail) ─────────────────────────────
    def _poly(surf, pts, col, alpha):
        try:
            gfxdraw.filled_polygon(surf, pts, (*col, alpha))
            gfxdraw.aapolygon(surf, pts, (*col, alpha))
        except Exception:
            pygame.draw.polygon(surf, col, pts)

    def _disc(surf, x, y, r, col, alpha):
        try:
            gfxdraw.filled_circle(surf, x, y, r, (*col, alpha))
            gfxdraw.aacircle(surf, x, y, r, (*col, alpha))
        except Exception:
            pygame.draw.circle(surf, col, (x, y), r)

    def _gull(surf, cx, cy, flap, scale, col, alpha=255):
        """A seagull in flight as a single silhouette: the classic shallow-'M'
        with a bent 'wrist' and pointed tips. ``flap`` in [-1,1] raises/lowers
        the wings."""
        cx, cy = int(cx), int(cy)
        s = scale * SS
        lift = (5 + flap * 13) * s            # wing height (flap)
        wrist = 17 * s                        # distance out to the wrist bend
        tipd = 42 * s                         # distance out to the wing tip
        for side in (-1, 1):
            pts = [
                (cx, cy + 3 * s),                              # under the body
                (cx + side * 6 * s, cy - lift * 0.45),         # inner wing, rising
                (cx + side * wrist, cy - lift),                # wrist (high point)
                (cx + side * tipd, cy - lift * 0.30),          # pointed tip, lower
                (cx + side * tipd * 0.96, cy - lift * 0.12),   # tip underside
                (cx + side * wrist * 0.92, cy - lift * 0.5),   # wrist underside
                (cx + side * 5 * s, cy + 1 * s),               # back toward body
            ]
            _poly(surf, [(int(px), int(py)) for px, py in pts], col, alpha)
        # slim body + small head nub
        _poly(surf, [
            (cx - int(2.4 * s), cy),
            (cx + int(2.4 * s), cy),
            (cx + int(1.4 * s), cy + int(9 * s)),
            (cx - int(1.4 * s), cy + int(9 * s)),
        ], col, alpha)
        _disc(surf, cx, cy - int(2 * s), max(1, int(2.2 * s)), col, alpha)

    # ── Pre-computed numpy masks for post-processing ──────────────────────────
    if have_np:
        ax = (np.arange(BASE_W) - BASE_W / 2) / (BASE_W / 2)
        ay = (np.arange(BASE_H) - BASE_H / 2) / (BASE_H / 2)
        d2 = ax[:, None] ** 2 + ay[None, :] ** 2
        vignette = np.clip(1.0 - d2 * 0.34, 0.32, 1.0).astype(np.float32)
        edge_mask = np.clip(d2 * 1.15, 0.0, 1.0).astype(np.float32)
        # reflection helper arrays (window resolution — 6× cheaper than SS)
        n_water_w = BASE_H - HZ_w
        w_ys_w = np.arange(n_water_w)
        w_xs_w = np.arange(BASE_W)
        sun_cx_w = int(BASE_W * SUN_FRAC)

        def _aces(x):
            return np.clip((x * (2.51 * x + 0.03)) /
                           (x * (2.43 * x + 0.59) + 0.14), 0.0, 1.0)

    # Debug: GULLWING_SPLASH_DUMP="path.png@0.6" saves one frame at the given
    # progress and exits. Harmless in production (env var unset).
    dump_path, dump_at, dumped = None, 0.6, False
    _dump = os.environ.get("GULLWING_SPLASH_DUMP")
    if _dump:
        if "@" in _dump:
            dump_path, _a = _dump.rsplit("@", 1)
            try:
                dump_at = float(_a)
            except ValueError:
                pass
        else:
            dump_path = _dump

    clock = pygame.time.Clock()
    start = pygame.time.get_ticks()
    fade_in, fade_out = 0.5, 0.7

    # gull motion-blur history (previous positions for ghosting)
    prev_formation = [None]

    running = True
    while running:
        now = pygame.time.get_ticks()
        elapsed = (now - start) / 1000.0
        if elapsed >= duration:
            break
        t = elapsed
        progress = max(0.0, min(1.0, elapsed / duration))

        for ev in pygame.event.get():
            if ev.type == pygame.QUIT:
                running = False
            elif ev.type == pygame.KEYDOWN and ev.key in (
                    pygame.K_ESCAPE, pygame.K_RETURN, pygame.K_SPACE):
                running = False

        # ── Compose above-horizon scene ───────────────────────────────────────
        scene.blit(sky, (0, 0))
        glow.fill((0, 0, 0, 0))

        # Twinkling stars (fade toward horizon)
        for sx, sy, b, ph in star_pts:
            tw = 0.55 + 0.45 * math.sin(t * 2.0 + ph)
            bb = _clamp(b * tw)
            scene.set_at((sx, sy), (bb, bb, _clamp(bb + 20)))

        # Sun — small, soft, warm, sitting just above the horizon and offset
        # from centre so its bright water-reflection column doesn't fall behind
        # the centred title text. Drawn straight onto the scene (not the bloom
        # layer) so it can't blow out to a white supernova.
        sun_x, sun_y = int(W * SUN_FRAC), HZ - int(10 * SS)
        for rr, col in ((int(58 * SS), (150, 70, 48)),
                        (int(40 * SS), (196, 96, 52)),
                        (int(26 * SS), (236, 138, 66)),
                        (int(16 * SS), (252, 186, 110)),
                        (int(9 * SS), (255, 226, 168))):
            try:
                gfxdraw.filled_circle(scene, sun_x, sun_y, rr, col)
            except Exception:
                pygame.draw.circle(scene, col, (sun_x, sun_y), rr)
        # A gentle bloom seed for the sun core only
        gfxdraw.filled_circle(glow, sun_x, sun_y, int(14 * SS), (255, 210, 150, 150))

        # Clouds (dark top, warm-lit underbelly)
        for cl in clouds:
            cl["x"] = (cl["x"] - cl["spd"] * (1 / 45.0))
            if cl["x"] < -cl["w"]:
                cl["x"] = W + cl["w"] * 0.5
            base_x = cl["x"]
            for pi in range(cl["puffs"]):
                fx = base_x + (pi / max(1, cl["puffs"] - 1) - 0.5) * cl["w"]
                pr = cl["h"] * (0.7 + 0.5 * math.sin(cl["seed"] + pi))
                fy = cl["y"] + math.sin(cl["seed"] * 2 + pi) * cl["h"] * 0.3
                # dark body
                cd = pygame.Surface((int(pr * 2.4), int(pr * 1.8)),
                                    pygame.SRCALPHA)
                pygame.draw.ellipse(cd, (40, 24, 40, 120),
                                    (0, 0, int(pr * 2.4), int(pr * 1.8)))
                scene.blit(cd, (int(fx - pr * 1.2), int(fy - pr * 0.9)))
                # warm underbelly
                cu = pygame.Surface((int(pr * 2.0), int(pr * 0.9)),
                                    pygame.SRCALPHA)
                pygame.draw.ellipse(cu, (255, 150, 80, 70),
                                    (0, 0, int(pr * 2.0), int(pr * 0.9)))
                scene.blit(cu, (int(fx - pr), int(fy)))

        # ── Venice canal — palazzo facades on both banks (far → near) ─────────
        z_cam = SPEED * t
        while segments and segments[0]["z0"] + segments[0]["len"] - z_cam < NEAR:
            segments.pop(0)
        far_end = (segments[-1]["z0"] + segments[-1]["len"]) if segments \
            else z_cam + NEAR
        while far_end - z_cam < FAR:
            s = _gen_seg(far_end)
            segments.append(s)
            far_end += s["len"]

        hw = CW
        for seg in reversed(segments):
            z0 = max(seg["z0"] - z_cam, NEAR)
            z1 = max(seg["z0"] + seg["len"] - z_cam, NEAR + 0.01)
            if z0 >= FAR:
                continue
            z1 = min(z1, FAR)
            fog = max(0.22, 1.0 - (z0 / FAR) * 0.92)
            for side, bh, fac, rows, cols, lit in (
                (-1, seg["lh"], seg["lc"], seg["lrows"], seg["lcols"], seg["lwin"]),
                (+1, seg["rh"], seg["rc"], seg["rrows"], seg["rcols"], seg["rwin"]),
            ):
                x = side * hw
                bx0, by0, _ = proj(x, 0, z0)
                bx1, by1, _ = proj(x, 0, z1)
                tx0, ty0, _ = proj(x, bh, z0)
                tx1, ty1, _ = proj(x, bh, z1)
                # Dark backlit silhouette
                fc = _silhouette(fac, fog)
                pygame.draw.polygon(scene, fc, [(bx0, by0), (bx1, by1),
                                                (tx1, ty1), (tx0, ty0)])
                # Rooftop catches a thin rim of sky light
                pygame.draw.line(scene, _shade(fc, 1.7),
                                 (tx0, ty0), (tx1, ty1), max(1, SS))
                # Faint limestone waterline (kept subtle so the silhouette holds)
                sx0, sy0, _ = proj(x, 0.4, z0)
                sx1, sy1, _ = proj(x, 0.4, z1)
                pygame.draw.polygon(scene, _shade(_STONE, fog * 0.4),
                                    [(bx0, by0), (bx1, by1), (sx1, sy1), (sx0, sy0)])
                # Rows of warm windows up the facade — the key "this is a
                # building" cue. Drawn solid on the scene (so they read even with
                # bloom dialled down) plus a small bloom seed on the glow layer.
                if lit and z0 < 26:
                    nrows = rows + 2
                    for ri in range(nrows):
                        wy_w = bh * (0.22 + 0.62 * ri / max(1, nrows))
                        for ci in range(cols):
                            wz = z0 + (z1 - z0) * ((ci + 0.5) / cols)
                            wpx, wpy, ws = proj(x, wy_w, wz)
                            wr = max(1, int(ws * 0.07))
                            wh2 = max(1, int(wr * 1.7))
                            # dark recess frame
                            pygame.draw.rect(scene, _shade((22, 15, 12), fog),
                                             (int(wpx - wr - 1), int(wpy - wh2 - 1),
                                              wr * 2 + 2, wh2 + 2))
                            # not every window is lit — gives life/variation
                            if (ri * 7 + ci * 3 + seg["lrows"]) % 5 == 0:
                                pane = _shade((40, 44, 60), fog)   # dark pane
                            else:
                                warm = (255, 206, 120) if (ri + ci) % 2 == 0 \
                                    else (250, 176, 84)
                                pane = _shade(warm, min(1.0, fog * 1.08))
                                pygame.draw.rect(
                                    glow, (*warm, _clamp(140 * fog)),
                                    (int(wpx - wr), int(wpy - wh2), wr * 2, wh2))
                            pygame.draw.rect(scene, pane,
                                             (int(wpx - wr), int(wpy - wh2),
                                              wr * 2, wh2))
            # Striped mooring pole
            if seg["pole"] and z0 < 16:
                px = seg["pside"] * (hw - 0.3)
                pz = (z0 + z1) / 2
                p0x, p0y, ps = proj(px, 0, pz)
                p1x, p1y, _ = proj(px, 2.0, pz)
                pw = max(1, int(ps * 0.055))
                fade = max(0.4, 1 - pz / 18)
                c1, c2 = seg["pcol"]
                for bi in range(5):
                    yy0 = p0y + (p1y - p0y) * bi / 5
                    yy1 = p0y + (p1y - p0y) * (bi + 1) / 5
                    pc = _shade(c1 if bi % 2 == 0 else c2, fade)
                    pygame.draw.line(scene, pc, (p0x, yy0), (p0x, yy1), pw * 2)
                _disc(scene, int(p0x), int(p1y), max(1, pw),
                      _shade((40, 50, 70), fade), 255)
            # Moored gondola
            if seg["gond"] and z0 < 14:
                gx_w = seg["gside"] * (hw - 0.85)
                gz = (z0 + z1) / 2
                gsx, gsy, gs = proj(gx_w, 0.04, gz)
                gw = max(4, int(gs * 0.42))
                gh = max(2, int(gs * 0.09))
                gc = _shade((14, 10, 16), max(0.4, 1 - gz / 14))
                pygame.draw.polygon(scene, gc, [
                    (gsx - gw, gsy - gh), (gsx + gw, gsy - gh),
                    (gsx + int(gw * 0.6), gsy + gh),
                    (gsx - int(gw * 0.6), gsy + gh)])
                pygame.draw.line(scene, gc, (gsx - int(gw * 0.5), gsy - gh),
                                 (gsx - int(gw * 0.2), gsy - gh * 5),
                                 max(1, int(gs * 0.02)))

        # Horizon haze (soft, low — gives atmospheric depth without a hard band)
        haze = pygame.Surface((W, int(46 * SS)), pygame.SRCALPHA)
        for i in range(int(46 * SS)):
            tnorm = i / (46 * SS)
            aa = int(46 * (1 - abs(tnorm - 0.5) * 2))   # peak in the middle
            pygame.draw.line(haze, (255, 158, 100, aa), (0, i), (W, i))
        scene.blit(haze, (0, HZ - int(23 * SS)))

        # ── Seagulls gliding down the canal toward the sunset ─────────────────
        # Dark backlit silhouettes — the iconic "gull at sunset" — with a hero
        # bird close to camera and the flock receding toward the vanishing point.
        flap = math.sin(t * 2.4 * 2 * math.pi)
        gull_col = (26, 22, 30)
        cx0 = W * 0.53 + math.sin(t * 0.6) * 55 * SS
        cy0 = HZ - 86 * SS + math.sin(t * 1.3) * 13 * SS
        formation = [
            (cx0, cy0, 1.95, 255),                                         # hero
            (cx0 - 104 * SS + math.sin(t * 0.8) * 18 * SS,
             cy0 - 34 * SS + math.sin(t * 1.2) * 9 * SS, 0.9, 255),
            (cx0 + 92 * SS + math.sin(t * 0.7 + 2) * 16 * SS,
             cy0 - 18 * SS + math.sin(t * 1.0 + 1) * 8 * SS, 0.62, 255),
            (cx0 - 24 * SS + math.sin(t * 0.9 + 1) * 12 * SS,
             cy0 - 58 * SS + math.sin(t * 1.4) * 7 * SS, 0.40, 255),       # far
        ]
        # faint motion-blur ghost of the previous frame for a sense of speed
        if prev_formation[0]:
            for gx, gy, sc, al in prev_formation[0]:
                _gull(scene, gx, gy, flap, sc, gull_col, 60)
        prev_formation[0] = formation
        for gx, gy, sc, al in formation:
            _gull(scene, gx, gy, flap, sc, gull_col, al)

        # Embers on glow
        for e in embers:
            e["y"] -= e["vy"] * (1 / 45.0)
            e["x"] += math.sin(t + e["ph"]) * e["drift"] * (1 / 45.0)
            if e["y"] < -5:
                e["y"] = H + 5
                e["x"] = rng.uniform(0, W)
            tw = 0.5 + 0.5 * math.sin(t * 3 + e["ph"])
            col = (255, 170, 80) if e["warm"] else (160, 200, 255)
            try:
                gfxdraw.filled_circle(glow, int(e["x"]), int(e["y"]),
                                      max(1, int(e["r"])), (*col, _clamp(150 * tw)))
            except Exception:
                pass

        # ── Bloom composite ───────────────────────────────────────────────────
        scene.blit(_bloom(glow), (0, 0), special_flags=pygame.BLEND_RGB_ADD)

        # ── Downsample to window (supersampled AA) ────────────────────────────
        pygame.transform.smoothscale(scene, (BASE_W, BASE_H), screen)

        # ── Water: real rippled reflection of the whole scene (window res) ────
        if have_np:
            try:
                _reflect_np(np, pygame, screen, BASE_W, BASE_H, HZ_w,
                            sun_cx_w, t, w_xs_w, w_ys_w, n_water_w)
            except Exception:
                _reflect_simple(pygame, screen, BASE_W, BASE_H, HZ_w)
        else:
            _reflect_simple(pygame, screen, BASE_W, BASE_H, HZ_w)

        # ── Per-pixel post: filmic tone-map, grade, vignette, CA, grain ───────
        if have_np:
            try:
                _post_np(np, pygame, screen, BASE_W, BASE_H,
                         vignette, edge_mask, _aces)
            except Exception:
                pass

        # ── Titles / progress (crisp, on top, after grain) ────────────────────
        _draw_titles(pygame, screen, BASE_W, BASE_H, f_title, f_sub, f_small,
                     progress, stages, version)

        # Fade in / out
        a = 0
        if t < fade_in:
            a = _clamp(255 * (1 - t / fade_in))
        elif t > duration - fade_out:
            a = _clamp(255 * (1 - (duration - t) / fade_out))
        if a > 0:
            ov = pygame.Surface((BASE_W, BASE_H))
            ov.fill((3, 2, 12))
            ov.set_alpha(a)
            screen.blit(ov, (0, 0))

        if dump_path and not dumped and progress >= dump_at:
            try:
                pygame.image.save(screen, dump_path)
            except Exception:
                pass
            dumped = True
            running = False

        pygame.display.flip()
        clock.tick(45)

    pygame.quit()
    return True


# ── Water reflection (numpy fast path) ───────────────────────────────────────────

def _reflect_np(np, pygame, surf, W, H, HZ, sun_cx, t, w_xs, w_ys, n_water):
    arr = pygame.surfarray.pixels3d(surf)           # (W, H, 3) uint8 view
    # Mirror source rows (slight compression so the reflection foreshortens)
    src_y = (HZ - 1 - (w_ys * 0.92)).astype(np.int32)
    np.clip(src_y, 0, HZ - 1, out=src_y)
    # Two-frequency horizontal ripple, amplitude grows toward the viewer
    amp = (1.5 + w_ys * 0.05)
    phase = t * 3.0
    offs = (amp * np.sin(0.05 * w_ys + phase)
            + amp * 0.5 * np.sin(0.13 * w_ys + phase * 1.7))
    offs = offs.astype(np.int32)
    src_x = (w_xs[:, None] + offs[None, :]) % W      # (W, n)
    src_y2d = np.broadcast_to(src_y[None, :], src_x.shape)
    refl = arr[src_x, src_y2d, :].astype(np.float32)  # (W, n, 3)
    # Fresnel: reflection stronger near the horizon, fading with depth
    fade = (1.0 - w_ys / n_water * 0.8)[None, :, None]
    water = np.array([9, 28, 44], np.float32)
    out = refl * (fade * 0.88) + water * (1.0 - fade * 0.88)
    out *= 0.84
    # Sun-glitter sparkles concentrated on the sun's column, near the horizon
    sparkle = (np.random.rand(W, n_water) > 0.9986).astype(np.float32)
    colw = np.exp(-((w_xs - sun_cx) ** 2) / (2 * (W * 0.11) ** 2))[:, None]
    depthw = (1.0 - w_ys / n_water)[None, :]
    sparkle = sparkle * colw * depthw
    out += sparkle[..., None] * np.array([255, 232, 176], np.float32) * 3.2
    np.clip(out, 0, 255, out=out)
    arr[:, HZ:, :] = out.astype(np.uint8)
    del arr


def _reflect_simple(pygame, scene, W, H, HZ):
    """numpy-free fallback: flipped, darkened, blue-tinted mirror."""
    above = scene.subsurface((0, 0, W, HZ)).copy()
    mirror = pygame.transform.flip(above, False, True)
    mh = H - HZ
    mirror = pygame.transform.smoothscale(mirror, (W, mh))
    mirror.set_alpha(150)
    scene.fill((9, 28, 44), (0, HZ, W, mh))
    scene.blit(mirror, (0, HZ))
    tint = pygame.Surface((W, mh), pygame.SRCALPHA)
    tint.fill((8, 26, 44, 90))
    scene.blit(tint, (0, HZ))


# ── Per-pixel post-processing (numpy) ────────────────────────────────────────────

def _post_np(np, pygame, screen, W, H, vignette, edge_mask, aces):
    arr = pygame.surfarray.pixels3d(screen)         # (W, H, 3) uint8 view
    f = arr.astype(np.float32) / 255.0
    # Filmic tone-map (no extra exposure — the scene was over-bright)
    f = aces(f * 0.98)
    # Colour grade: lift shadows slightly cool, warm the highlights
    luma = f[..., 0] * 0.299 + f[..., 1] * 0.587 + f[..., 2] * 0.114
    warm = np.clip((luma - 0.55) * 1.6, 0, 1)[..., None]
    f[..., 0] += warm[..., 0] * 0.05
    f[..., 2] += (1 - luma)[..., None][..., 0] * 0.025
    # Vignette
    f *= vignette[..., None]
    # Subtle chromatic aberration toward the edges
    r = f[..., 0]
    b = f[..., 2]
    r_sh = np.roll(r, 1, axis=0)
    b_sh = np.roll(b, -1, axis=0)
    f[..., 0] = r * (1 - edge_mask) + r_sh * edge_mask
    f[..., 2] = b * (1 - edge_mask) + b_sh * edge_mask
    # Film grain (subtle)
    f += (np.random.rand(W, H, 1).astype(np.float32) - 0.5) * 0.016
    np.clip(f, 0, 1, out=f)
    arr[:] = (f * 255).astype(np.uint8)
    del arr


# ── Title / progress overlay ─────────────────────────────────────────────────────

def _draw_titles(pygame, screen, W, H, f_title, f_sub, f_small,
                 progress, stages, version):
    # Dark gradient scrim across the bottom so text is always legible over the
    # water reflection / sun glitter — this is what fixes "text blocked by the
    # sun and gulls". Built fresh (cheap) each call.
    band = 132
    scrim = pygame.Surface((W, band), pygame.SRCALPHA)
    for i in range(band):
        a = int(195 * (i / band) ** 1.5)
        pygame.draw.line(scrim, (4, 7, 16, a), (0, i), (W, i))
    screen.blit(scrim, (0, H - band))

    # Title — clean white with a soft drop shadow (no oversized glow)
    title = f_title.render("GULLWING", True, (238, 244, 252))
    shadow = f_title.render("GULLWING", True, (2, 4, 10))
    ty = H - 86
    tx = W // 2 - title.get_width() // 2
    screen.blit(shadow, (tx + 1, ty + 2))
    screen.blit(title, (tx, ty))

    sub = f_sub.render(
        "Tune it.  ·  Lock it.  ·  Send it.",
        True, (170, 184, 202))
    screen.blit(sub, (W // 2 - sub.get_width() // 2,
                      ty + title.get_height() + 6))

    bar_w, bar_h = 300, 5
    bx = W // 2 - bar_w // 2
    by = H - 26
    pygame.draw.rect(screen, (13, 24, 36), (bx, by, bar_w, bar_h),
                     border_radius=bar_h // 2)
    filled = int(bar_w * progress)
    if filled > 2:
        fill = pygame.Surface((bar_w, bar_h), pygame.SRCALPHA)
        pygame.draw.rect(fill, (0, 184, 220), (0, 0, filled, bar_h),
                         border_radius=bar_h // 2)
        glowbar = pygame.transform.smoothscale(
            pygame.transform.smoothscale(fill, (max(1, bar_w // 5),
                                                max(1, bar_h))),
            (bar_w, bar_h))
        screen.blit(glowbar, (bx, by), special_flags=pygame.BLEND_RGB_ADD)
        screen.blit(fill, (bx, by))

    stage = stages[0][1]
    for thr, label in reversed(stages):
        if progress >= thr:
            stage = label
            break
    pct = int(progress * 100)
    vtxt = f" · v{version}" if version else ""
    info = f_small.render(f"{stage}   {pct}%{vtxt}", True, (122, 142, 162))
    screen.blit(info, (W // 2 - info.get_width() // 2, by + 14))


if __name__ == "__main__":
    run_splash(version="dev")
