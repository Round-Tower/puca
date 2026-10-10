#!/usr/bin/env python3
"""Generate assets/hero.svg — Púca's animated README banner.

    python3 scripts/readme_hero.py            # needs fonttools + brotli (pip install fonttools brotli)

One self-contained SVG that GitHub animates inside an <img>: CSS keyframes only, no
<script>, no external fetches (the image proxy drops both).

- The púca is the README's own block art (assets/puca-mark.txt), read cell by cell:
  each character is two square half-cells, so █ ▄ ▀ ▘ map exactly onto a 16×30 grid.
  Its enclosed holes are the eyes, lit lavender.
- It shapeshifts — hare, goat, black dog, back to the púca — as stepped frames whose
  cells dissolve and re-form, holding longest on the púca.
- Behind it, the road at night: probes leave its feet along curved lanes to the
  targets on the horizon. Targets inside scope.yaml's dashed boundary light up; the one
  outside it never gets a probe — its lane stops at the boundary in red. No scope, no fire.
- Palette is the HTML report's dark mode (puca/report/html.py). Type: Inter 600 for the
  name, IBM Plex Mono for the rest — both OFL, subset to the characters used and inlined.

Signed: Kev + claude-opus-5-5, 2026-10-07, Confidence 0.75. Prior: Unknown (new file).
Verified by eye in headless Chrome (page and <img>), with reduced motion forced, and in
WebKit via Quick Look. The three folklore forms are drawn by hand and are taste.
"""
from __future__ import annotations

import base64
import io
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets/hero.svg"
MARK = ROOT / "assets/puca-mark.txt"
INTER = ROOT / "assets/fonts/inter-latin-600-normal.woff2"
PLEX = ROOT / "assets/fonts/ibm-plex-mono-latin-400-normal.woff2"

W, H = 1280, 440
TX = 72

# The report's dark mode (puca/report/html.py), plus the OWASP badge purple and the
# critical-severity red that marks "no scope, no fire".
BG, PANEL, FG, MUTED, LINE, ACCENT = "#14131a", "#1d1b24", "#e8e5ee", "#a49fb0", "#312e3a", "#b9a6e6"
PURPLE, RED = "#5b2a86", "#a11235"

EYEBROW = "WHITE-HAT  ·  OWASP-MAPPED  ·  WEB  ·  API  ·  AGENTIC / MCP"
TITLE = "Púca"
TAGLINE = "Meets your systems on the road and tests them."
# Each chip is checked against the code, not just the README: owasp.py carries
# WEB_TOP_10_2021, LLM_TOP_10_2026 and AGENTIC_TOP_10_2026 (ASI01–ASI10) — there is
# no API Top 10 catalogue, so the chip says Web only; docker/ is FROM kali-rolling.
CHIPS = ["No scope, no fire", "OWASP Web Top 10", "LLM Top 10 (2026)", "Agentic ASI01–ASI10",
         "Kali in a box", "MIT"]
LABEL = "scope.yaml"


# ── The púca, from its block art ───────────────────────────────────────────
HALVES = {"█": (1, 1), "▄": (0, 1), "▀": (1, 0), "▘": (1, 0), " ": (0, 0), "⠀": (0, 0)}


def parse_block_art(text: str) -> list[str]:
    """Block art → rows of '#'/'.'; every character is a top and a bottom half-cell."""
    lines = [ln for ln in text.splitlines() if ln.strip(" ⠀")]
    width = max(len(ln) for ln in lines)
    rows: list[str] = []
    for line in lines:
        top, bottom = [], []
        for ch in line.ljust(width):
            if ch not in HALVES:
                raise ValueError(f"no half-cell mapping for {ch!r}")
            t, b = HALVES[ch]
            top.append("#" if t else ".")
            bottom.append("#" if b else ".")
        rows += ["".join(top), "".join(bottom)]
    return rows


def eyes(rows: list[str]) -> list[str]:
    """Holes the body fully encloses become eyes ('o'): flood the outside, keep the rest."""
    h, w = len(rows), len(rows[0])
    outside: set[tuple[int, int]] = set()
    stack = [(r, c) for r in range(h) for c in range(w) if (r in (0, h - 1) or c in (0, w - 1))]
    while stack:
        r, c = stack.pop()
        if not (0 <= r < h and 0 <= c < w) or (r, c) in outside or rows[r][c] == "#":
            continue
        outside.add((r, c))
        stack += [(r + 1, c), (r - 1, c), (r, c + 1), (r, c - 1)]
    return ["".join("o" if ch == "." and (r, c) not in outside else ch for c, ch in enumerate(row))
            for r, row in enumerate(rows)]


# Hand-drawn forms on the púca's 16×30 grid, standing on the same row ('o' = eye).
HARE = [
    "...##......##...", "..####....####..", "..####....####..", "..####....####..",
    "..####....####..", "..####....####..", "...###....###...", "...###....###...",
    "...###....###...", "....##....##....", "...##########...", "..############..",
    ".##############.", ".###oo####oo###.", ".###oo####oo###.", ".##############.",
    ".######..######.", "..#####..#####..", "...##########...", "....########....",
    "...##########...", "..############..", ".##############.", ".##############.",
    ".##############.", ".##############.", "..############..", "..####....####..",
    ".#####....#####.", "................",
]
GOAT = [
    "#..............#", "##............##", ".##..........##.", ".###........###.",
    "..####....####..", "...###....###...", "....########....", "..############..",
    ".##.########.##.", "....#oo##oo#....", "....########....", ".....######.....",
    ".....######.....", ".....######.....", "......####......", "......####......",
    ".......##.......", ".......##.......", "....########....", "...##########...",
    "..############..", "..############..", "..############..", "..############..",
    "...##########...", "...##.##..##.##.", "...##.##..##.##.", "...##.##..##.##.",
    "..###.##..##.###", "................",
]
DOG = [
    "................", "................", "...#........#...", "...##......##...",
    "...###....###...", "...##########...", "..############..", "..##oo####oo##..",
    "..############..", "...##########...", "....########....", ".....######.....",
    "......####......", ".....######.....", "....########....", "...##########...",
    "...##########...", "..############..", "..############..", ".##############.",
    ".##############.", "################", "################", "################",
    "####.######.####", "###..##..##..###", "###..##..##..###", "###..##..##..###",
    "####.###.###.###", "................",
]

HOLD_PUCA, HOLD_FORM = 4.2, 1.6   # seconds
SHIFT_STEPS, SHIFT_STEP = 7, 0.08  # a dissolve of seven quick frames


def shift_frames(a: list[str], b: list[str], seed: int) -> list[tuple[list[str], set[tuple[int, int]]]]:
    """Frames dissolving a → b: each differing cell flips at its own (seeded) step.
    Returns (frame, cells in flight) — in-flight cells are drawn lavender."""
    diff = [(r, c) for r in range(len(a)) for c in range(len(a[0])) if a[r][c] != b[r][c]]
    rng = random.Random(seed)
    rng.shuffle(diff)
    out = []
    for k in range(1, SHIFT_STEPS + 1):
        flipped = set(diff[: len(diff) * k // (SHIFT_STEPS + 1)])
        frame = [
            "".join(b[r][c] if (r, c) in flipped else a[r][c] for c in range(len(a[0])))
            for r in range(len(a))
        ]
        window = set(diff[len(diff) * (k - 1) // (SHIFT_STEPS + 1): len(diff) * (k + 1) // (SHIFT_STEPS + 1)])
        out.append((frame, window))
    return out


def sequence(puca: list[str]) -> list[tuple[list[str], set[tuple[int, int]], float]]:
    """(frame, in-flight cells, seconds) for one loop: púca → hare → goat → dog → púca."""
    forms = [puca, HARE, GOAT, DOG]
    seq: list[tuple[list[str], set[tuple[int, int]], float]] = []
    for i, form in enumerate(forms):
        seq.append((form, set(), HOLD_PUCA if i == 0 else HOLD_FORM))
        nxt = forms[(i + 1) % len(forms)]
        seq += [(f, fl, SHIFT_STEP) for f, fl in shift_frames(form, nxt, seed=i)]
    return seq


# ── Drawing ────────────────────────────────────────────────────────────────
CELL = 8.2
PUCA_X, PUCA_FEET = 1150, 404


def cells_d(cells: list[tuple[int, int]], x0: float, y0: float) -> str:
    side = CELL - 2.4
    return "".join(f"M{x0 + c * CELL + 1.2:.1f} {y0 + r * CELL + 1.2:.1f}h{side:.1f}v{side:.1f}h-{side:.1f}z"
                   for r, c in cells)


def frame_svg(frame: list[str], flight: set[tuple[int, int]], kind: str = "") -> str:
    x0 = PUCA_X - len(frame[0]) * CELL / 2
    y0 = PUCA_FEET - (len(frame) - 1) * CELL
    body = [(r, c) for r, row in enumerate(frame) for c, ch in enumerate(row) if ch == "#" and (r, c) not in flight]
    eye = [(r, c) for r, row in enumerate(frame) for c, ch in enumerate(row) if ch == "o"]
    fly = [(r, c) for r, c in flight if frame[r][c] == "#"]
    parts = [f'<path class="body{kind}" d="{cells_d(body, x0, y0)}"/>']
    if eye:
        parts.append(f'<path class="eye{kind}" d="{cells_d(eye, x0, y0)}"/>')
    if fly:
        parts.append(f'<path class="fly" d="{cells_d(fly, x0, y0)}"/>')
    return "".join(parts)


def shapeshift_layer(puca: list[str]) -> tuple[str, str]:
    seq = sequence(puca)
    total = sum(s for _, _, s in seq)
    groups, css, t = [], [], 0.0
    for i, (frame, flight, secs) in enumerate(seq):
        a, b = 100 * t / total, 100 * (t + secs) / total
        # Visible on [a, b): hard edges via a 0.001 % ramp. Frame 0 is the reduced-motion still.
        css.append(f"@keyframes s{i}{{0%{{opacity:{1 if i == 0 else 0}}}"
                   + (f"{a:.3f}%{{opacity:0}}{a + 0.001:.3f}%{{opacity:1}}" if i else "")
                   + f"{b:.3f}%{{opacity:1}}{b + 0.001:.3f}%{{opacity:0}}"
                   # frame 0 comes back only at the loop's very end: a ramp from b% would ghost it over every form
                   + ("99.999%{opacity:0}100%{opacity:1}}" if i == 0 else "100%{opacity:0}}")
                   + f".s{i}{{animation:s{i} {total:.2f}s linear infinite}}")
        kind = " dog" if frame is DOG else ""  # the black dog is black, with red eyes
        groups.append(f'<g class="shift s{i}">{frame_svg(frame, flight, kind)}</g>')
        t += secs
    return "".join(groups), "".join(css)


# ── The road, the probes, the scope ────────────────────────────────────────
VP = (826, 152)              # vanishing point on the horizon
ORIGIN = (1084, 410)         # the probes leave from beside the púca's feet
TARGETS = [(716, 140), (786, 126), (860, 132), (930, 120)]   # inside scope
OUTSIDE = (1044, 104)        # never in scope.yaml
SCOPE_BOX = (686, 98, 282, 64)   # x, y, w, h of the dashed scope boundary
PROBE_CYCLE = 3.6


def lane(end: tuple[float, float]) -> str:
    (ox, oy), (ex, ey) = ORIGIN, end
    cx, cy = (ox + VP[0]) / 2 + 30, (oy + VP[1]) / 2 + 40
    return f"M{ox} {oy}Q{cx:.0f} {cy:.0f} {ex} {ey}"


def gate_point(end: tuple[float, float]) -> tuple[float, float]:
    """Where a lane reaches the scope boundary's depth (its bottom edge): the gate.
    Inside scope the gate is open; the out-of-scope lane stops here."""
    (ox, oy), (ex, ey) = ORIGIN, end
    cx, cy = (ox + VP[0]) / 2 + 30, (oy + VP[1]) / 2 + 40
    gate_y = SCOPE_BOX[1] + SCOPE_BOX[3]
    for k in range(1001):
        u = k / 1000
        x = (1 - u) ** 2 * ox + 2 * (1 - u) * u * cx + u * u * ex
        y = (1 - u) ** 2 * oy + 2 * (1 - u) * u * cy + u * u * ey
        if y <= gate_y:
            return (round(x, 1), round(y, 1))
    return end


def cut_lane(end: tuple[float, float], stop: tuple[float, float]) -> str:
    """The lane toward `end`, cut at `stop` (same curve, sampled as a polyline)."""
    (ox, oy), (ex, ey) = ORIGIN, end
    cx, cy = (ox + VP[0]) / 2 + 30, (oy + VP[1]) / 2 + 40
    pts = []
    for k in range(41):
        u = k / 40
        x = (1 - u) ** 2 * ox + 2 * (1 - u) * u * cx + u * u * ex
        y = (1 - u) ** 2 * oy + 2 * (1 - u) * u * cy + u * u * ey
        if y < stop[1]:
            break
        pts.append(f"{x:.1f} {y:.1f}")
    pts.append(f"{stop[0]} {stop[1]}")
    return "M" + "L".join(pts)


def road_layer() -> tuple[str, str]:
    vx, vy = VP
    road = (f'<path class="road" d="M{vx - 4} {vy}L640 {H}M{vx + 4} {vy}L1300 {H}"/>'
            f'<path class="centre" d="M{vx} {vy}L{(vx + 1150) / 2:.0f} {H}"/>'
            f'<path class="horizon" d="M560 {vy}H{W}"/>')
    sx, sy, sw, sh = SCOPE_BOX
    scope = (f'<rect class="scope" x="{sx}" y="{sy}" width="{sw}" height="{sh}" rx="10"/>'
             f'<text class="mono label" x="{sx + 10}" y="{sy - 8}">{LABEL}</text>')
    lanes, probes, nodes = [], [], []
    n = len(TARGETS) + 1
    for i, (tx, ty) in enumerate(TARGETS):
        d = lane((tx, ty))
        delay = -i * PROBE_CYCLE / n
        lanes.append(f'<path class="lane" d="{d}"/>')
        probes.append(f'<path class="probe" pathLength="100" d="{d}" style="animation-delay:{delay:.2f}s"/>')
        nodes.append(f'<circle class="node" cx="{tx}" cy="{ty}" r="4.5"/>'
                     f'<circle class="hit" cx="{tx}" cy="{ty}" r="5" style="animation-delay:{delay:.2f}s"/>')
    fx, fy = gate_point(OUTSIDE)
    d = lane(OUTSIDE)
    cut = cut_lane(OUTSIDE, (fx, fy))
    delay = -(n - 1) * PROBE_CYCLE / n
    lanes.append(f'<path class="lane" d="{d}" stroke-dasharray="2 5"/>')
    probes.append(f'<path class="probe denied-probe" pathLength="100" d="{cut}" style="animation-delay:{delay:.2f}s"/>')
    nodes.append(f'<circle class="node out" cx="{OUTSIDE[0]}" cy="{OUTSIDE[1]}" r="4.5"/>'
                 f'<path class="gate" d="M{fx - 12} {fy}h24"/>'
                 f'<g class="deny" style="animation-delay:{delay:.2f}s"><circle cx="{fx}" cy="{fy}" r="9"/>'
                 f'<path d="M{fx - 4} {fy - 4}l8 8m0-8l-8 8"/></g>')
    css = (
        f".probe{{fill:none;stroke:{ACCENT};stroke-width:2.4;stroke-linecap:round;stroke-dasharray:7 200;"
        f"stroke-dashoffset:7;animation:probe {PROBE_CYCLE}s cubic-bezier(.45,0,.75,1) infinite}}"
        "@keyframes probe{0%{stroke-dashoffset:7;opacity:0}6%{opacity:1}64%{stroke-dashoffset:-93;opacity:1}"
        "66%,100%{stroke-dashoffset:-100;opacity:0}}"
        f".denied-probe{{stroke:{RED}}}"
        f".hit{{fill:{ACCENT};opacity:0;animation:hit {PROBE_CYCLE}s linear infinite}}"
        "@keyframes hit{0%,62%{opacity:0;r:4}66%{opacity:1;r:7}100%{opacity:0;r:4}}"
        f".deny{{opacity:0;animation:deny {PROBE_CYCLE}s linear infinite}}"
        "@keyframes deny{0%,62%{opacity:0}65%{opacity:1}88%,100%{opacity:0}}"
    )
    return road + scope + "".join(lanes) + "".join(nodes) + "".join(probes), css


# ── Fonts ──────────────────────────────────────────────────────────────────
def font_face(path: Path, family: str, text: str):  # type: ignore[no-untyped-def]
    from fontTools import subset  # only the writer needs fonttools (+ brotli for woff2)
    from fontTools.ttLib import TTFont

    font = TTFont(path, recalcTimestamp=False)  # a reproducible SVG: no fresh head.modified
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = ["kern"]
    sub = subset.Subsetter(options)
    sub.populate(text=text)
    sub.subset(font)
    buf = io.BytesIO()
    font.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"@font-face{{font-family:'{family}';src:url(data:font/woff2;base64,{b64}) format('woff2')}}", TTFont(path)


def advance(font, text: str, size: float, tracking: float = 0.0) -> float:  # type: ignore[no-untyped-def]
    cmap, hmtx, upm = font.getBestCmap(), font["hmtx"], font["head"].unitsPerEm
    return sum(hmtx[cmap[ord(ch)]][0] for ch in text) * size / upm + tracking * len(text)


# ── Compose ────────────────────────────────────────────────────────────────
def build() -> str:
    puca = eyes(parse_block_art(MARK.read_text()))
    inter_css, inter = font_face(INTER, "Inter", TITLE)
    plex_css, plex = font_face(PLEX, "Plex", EYEBROW + TAGLINE + "".join(CHIPS) + LABEL)
    shift, shift_css = shapeshift_layer(puca)
    road, road_css = road_layer()

    title_size, title_y = 124, 236
    title_w = advance(inter, TITLE, title_size, -2)
    chip_size, chip_h, pad, gap = 14.5, 32, 14, 9
    chips, cx, cy = [], TX, 326
    for k, label in enumerate(CHIPS):
        w = advance(plex, label, chip_size) + pad * 2
        if cx + w > 690:
            cx, cy = TX, cy + chip_h + gap
        lead = " lead" if k == 0 else ""
        chips.append(f'<g class="chip{lead}"><rect x="{cx:.1f}" y="{cy}" width="{w:.1f}" height="{chip_h}" rx="{chip_h / 2}"/>'
                     f'<text x="{cx + pad:.1f}" y="{cy + chip_h / 2 + 5:.1f}">{label}</text></g>')
        cx += w + gap

    rng = random.Random(7)
    TWINKLE = ' class="tw"'  # (no backslashes inside f-strings before 3.12)
    stars = "".join(
        f'<circle cx="{rng.uniform(560, W):.0f}" cy="{rng.uniform(8, 140):.0f}" r="{rng.choice((0.7, 0.9, 1.2))}"'
        f'{TWINKLE if k % 6 == 0 else ""} style="animation-delay:-{rng.uniform(0, 5):.1f}s"/>'
        for k in range(46))

    css = f"""{inter_css}{plex_css}
.mono{{font-family:'Plex',ui-monospace,Menlo,monospace}}
.eyebrow{{font-size:13.5px;letter-spacing:3px;fill:{MUTED}}}
.title{{font-family:'Inter',system-ui,sans-serif;font-weight:600;font-size:{title_size}px;letter-spacing:-2px;fill:url(#ink)}}
.tag{{font-size:21px;fill:{FG}}}
.chip rect{{fill:rgba(232,229,238,.04);stroke:rgba(232,229,238,.26);stroke-width:1}}
.chip text{{font-family:'Plex',ui-monospace,monospace;font-size:{chip_size}px;fill:#d6d1df}}
.lead rect{{fill:rgba(161,18,53,.22);stroke:#e0486b}}.lead text{{fill:#ffd9e1}}
.label{{font-size:11px;letter-spacing:1.5px;fill:{MUTED};opacity:.75}}
.road{{fill:none;stroke:{LINE};stroke-width:1.2}}
.centre{{fill:none;stroke:{LINE};stroke-width:1.4;stroke-dasharray:14 16}}
.horizon{{fill:none;stroke:{LINE};stroke-width:1;opacity:.8}}
.lane{{fill:none;stroke:{ACCENT};stroke-width:1;opacity:.16}}
.scope{{fill:rgba(185,166,230,.04);stroke:{ACCENT};stroke-width:1.1;stroke-dasharray:5 5;opacity:.6}}
.node{{fill:{PANEL};stroke:{ACCENT};stroke-width:1.4}}.node.out{{stroke:{MUTED};opacity:.5}}
.gate{{stroke:#e0486b;stroke-width:2.4;stroke-linecap:round}}
.deny circle{{fill:rgba(161,18,53,.35);stroke:#e0486b;stroke-width:1.4}}.deny path{{stroke:#ffd9e1;stroke-width:1.6;stroke-linecap:round}}
.stars circle{{fill:{FG};opacity:.35}}.stars .tw{{animation:tw 4.5s ease-in-out infinite}}
@keyframes tw{{50%{{opacity:.05}}}}
.body{{fill:#8b78c4;stroke:#8b78c4;stroke-width:1.2;stroke-linejoin:round}}
.eye{{fill:#fff;stroke:#fff;stroke-width:1.2;stroke-linejoin:round;filter:url(#eyeglow)}}
.fly{{fill:#e8e5ee;opacity:.7}}
.body.dog{{fill:#2b2440;stroke:#4a3d6e}}.eye.dog{{fill:#ff5c7a;stroke:#ff5c7a}}
{shift_css}
{road_css}
.shine{{animation:shine 8s cubic-bezier(.5,0,.3,1) infinite}}
@keyframes shine{{0%,58%{{transform:translateX(-220px) skewX(-18deg)}}86%,100%{{transform:translateX({title_w + 180:.0f}px) skewX(-18deg)}}}}
@media (prefers-reduced-motion:reduce){{
.shift,.probe,.hit,.deny,.tw,.shine{{animation:none}}
.shift{{opacity:0}}.s0{{opacity:1}}.probe,.hit,.deny{{opacity:0}}
}}"""

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d">
<title id="t">Púca — a white-hat security kit that meets your systems on the road and tests them</title>
<desc id="d">The púca, a pixel shapeshifter from Irish folklore, stands on a night road and shifts into a hare, a goat and a black dog. Probes leave its feet for targets on the horizon; those inside the scope boundary light up, and the one outside it is stopped at the boundary in red: no scope, no fire.</desc>
<!-- Generated by scripts/readme_hero.py — edit that, not this. -->
<style>{css}</style>
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#1a1822"/><stop offset=".6" stop-color="{BG}"/><stop offset="1" stop-color="#0d0c12"/></linearGradient>
<radialGradient id="halo" cx="{PUCA_X}" cy="{PUCA_FEET - 130}" r="230" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="{PURPLE}" stop-opacity=".55"/><stop offset=".55" stop-color="{PURPLE}" stop-opacity=".14"/><stop offset="1" stop-color="{PURPLE}" stop-opacity="0"/></radialGradient>
<linearGradient id="fade" x1="0" x2="1"><stop offset=".42" stop-color="#fff" stop-opacity="0"/><stop offset=".6" stop-color="#fff" stop-opacity="1"/></linearGradient>
<mask id="right"><rect width="{W}" height="{H}" fill="url(#fade)"/></mask>
<linearGradient id="ink" x1="0" y1="{title_y - title_size * .74:.0f}" x2="0" y2="{title_y}" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#b3aac4"/></linearGradient>
<linearGradient id="shineg" x1="0" x2="1"><stop offset="0" stop-color="{ACCENT}" stop-opacity="0"/><stop offset=".5" stop-color="#fff" stop-opacity=".95"/><stop offset="1" stop-color="{ACCENT}" stop-opacity="0"/></linearGradient>
<clipPath id="titleclip"><text x="{TX - 6}" y="{title_y}" font-family="Inter" font-weight="600" font-size="{title_size}" letter-spacing="-2">{TITLE}</text></clipPath>
<filter id="eyeglow" x="-200%" y="-200%" width="500%" height="500%"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<filter id="glow" x="-30%" y="-20%" width="160%" height="140%"><feGaussianBlur stdDeviation="3.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="{W}" height="{H}" fill="url(#bg)"/>
<g class="stars" mask="url(#right)">{stars}</g>
<g mask="url(#right)">{road}</g>
<circle cx="{PUCA_X}" cy="{PUCA_FEET - 130}" r="230" fill="url(#halo)"/>
<ellipse cx="{PUCA_X}" cy="{PUCA_FEET + 6}" rx="96" ry="9" fill="#000" opacity=".45"/>
<g filter="url(#glow)">{shift}</g>
<text class="mono eyebrow" x="{TX}" y="92">{EYEBROW}</text>
<text class="title" x="{TX - 6}" y="{title_y}">{TITLE}</text>
<g clip-path="url(#titleclip)"><rect class="shine" x="{TX}" y="{title_y - title_size}" width="110" height="{title_size + 30}" fill="url(#shineg)" opacity=".85"/></g>
<text class="mono tag" x="{TX}" y="{title_y + 50}">{TAGLINE}</text>
{"".join(chips)}
</svg>
"""


def main() -> None:
    svg = build()
    OUTPUT.write_text(svg)
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(svg.encode()) / 1024:.0f} KB)")


if __name__ == "__main__":
    main()

