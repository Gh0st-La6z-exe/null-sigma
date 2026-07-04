#!/usr/bin/env python3
"""Generate assets/benchmarks.svg from Criterion benchmark medians.

Dependency-free (stdlib only). To refresh after a benchmark run:

    cargo bench
    # update the numbers below from the Criterion output
    python3 scripts/gen_benchmark_chart.py

Left panel : per-event latency vs rule count (log-log), against the naive
             linear-scaling line — shows the prefilter's sublinear behavior.
Right panel: single-core throughput by scenario.
"""

import math
import os

# ── Data (Criterion medians, Apple M4, release, 2026-07-04) ─────────────────

# (rule count, per-event latency in µs) — *_rules_single_event benchmarks
SCALING = [(1, 1.3489), (100, 0.85634), (1000, 2.3405)]

# (label, events/sec) — derived throughput, single core
THROUGHPUT = [
    ("1000 rules · wrong logsource", 1_096_000),
    ("100 rules · 100-event batch", 1_072_000),
    ("1000 rules · no AC hit", 559_000),
    ("1000 rules · matching event", 427_000),
]

# ── Style ────────────────────────────────────────────────────────────────────

BG = "#161b22"
GRID = "#30363d"
TEXT = "#c9d1d9"
MUTED = "#8b949e"
BLUE = "#58a6ff"
GREEN = "#3fb950"
ORANGE = "#d29922"
FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"

W, H = 920, 400
OUT = os.path.join(os.path.dirname(__file__), "..", "assets", "benchmarks.svg")


def fmt_us(v: float) -> str:
    if v >= 1000:
        return f"{v / 1000:.3g} ms"
    if v >= 1:
        return f"{v:.3g} µs"
    return f"{v * 1000:.3g} ns"


def main() -> None:
    s: list[str] = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="{FONT}">'
    )
    s.append(f'<rect width="{W}" height="{H}" rx="10" fill="{BG}"/>')
    s.append(
        f'<text x="{W / 2}" y="30" fill="{TEXT}" font-size="16" font-weight="600" '
        f'text-anchor="middle">null-sigma — measured performance '
        f'(Apple M4, single core, Criterion medians)</text>'
    )

    # ── Left panel: latency vs rule count, log-log ───────────────────────────
    x0, x1, y0, y1 = 80, 430, 330, 70  # plot box (y grows downward)
    lat_lo, lat_hi = -1.0, 4.0  # log10 µs: 0.1 µs … 10 ms
    n_lo, n_hi = 0.0, 3.0  # log10 rules: 1 … 1000

    def px(rules: float) -> float:
        return x0 + (math.log10(rules) - n_lo) / (n_hi - n_lo) * (x1 - x0)

    def py(us: float) -> float:
        return y0 + (math.log10(us) - lat_lo) / (lat_hi - lat_lo) * (y1 - y0)

    s.append(
        f'<text x="{(x0 + x1) / 2}" y="58" fill="{TEXT}" font-size="13" '
        f'text-anchor="middle">Per-event latency vs rule count</text>'
    )
    for d in range(int(lat_lo), int(lat_hi) + 1):
        y = py(10**d)
        s.append(f'<line x1="{x0}" y1="{y:.1f}" x2="{x1}" y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>')
        s.append(
            f'<text x="{x0 - 8}" y="{y + 4:.1f}" fill="{MUTED}" font-size="11" '
            f'text-anchor="end">{fmt_us(10**d)}</text>'
        )
    for n in (1, 10, 100, 1000):
        x = px(n)
        s.append(f'<line x1="{x:.1f}" y1="{y0}" x2="{x:.1f}" y2="{y0 + 5}" stroke="{GRID}"/>')
        s.append(
            f'<text x="{x:.1f}" y="{y0 + 20}" fill="{MUTED}" font-size="11" '
            f'text-anchor="middle">{n}</text>'
        )
    s.append(
        f'<text x="{(x0 + x1) / 2}" y="{y0 + 40}" fill="{MUTED}" font-size="12" '
        f'text-anchor="middle">rules loaded (log scale)</text>'
    )

    # Naive linear reference: single-rule latency × N
    base = SCALING[0][1]
    s.append(
        f'<line x1="{px(1):.1f}" y1="{py(base):.1f}" x2="{px(1000):.1f}" y2="{py(base * 1000):.1f}" '
        f'stroke="{ORANGE}" stroke-width="2" stroke-dasharray="6 5"/>'
    )
    s.append(
        f'<text x="{px(180):.1f}" y="{py(base * 180) - 10:.1f}" fill="{ORANGE}" '
        f'font-size="11" text-anchor="middle" transform="rotate(-24 {px(180):.0f} {py(base * 180) - 10:.0f})">'
        f'naive linear (1-rule cost × N)</text>'
    )

    # Measured curve
    pts = " ".join(f"{px(n):.1f},{py(us):.1f}" for n, us in SCALING)
    s.append(f'<polyline points="{pts}" fill="none" stroke="{BLUE}" stroke-width="2.5"/>')
    for n, us in SCALING:
        s.append(f'<circle cx="{px(n):.1f}" cy="{py(us):.1f}" r="4.5" fill="{BLUE}"/>')
        anchor = "start" if n == 1 else "middle"
        s.append(
            f'<text x="{px(n) + (10 if n == 1 else 0):.1f}" y="{py(us) - 12:.1f}" fill="{TEXT}" '
            f'font-size="11" text-anchor="{anchor}">{fmt_us(us)}</text>'
        )
    s.append(
        f'<text x="{px(1000):.1f}" y="{py(SCALING[-1][1]) + 32:.1f}" fill="{GREEN}" '
        f'font-size="12" font-weight="600" text-anchor="end">'
        f'{base * 1000 / SCALING[-1][1]:.0f}× below naive linear at 1000 rules</text>'
    )

    # ── Right panel: throughput bars ─────────────────────────────────────────
    bx0, bx1 = 540, 880
    s.append(
        f'<text x="{(bx0 + bx1) / 2}" y="58" fill="{TEXT}" font-size="13" '
        f'text-anchor="middle">Throughput by scenario (events/sec)</text>'
    )
    vmax = 1_200_000
    bar_h, gap, top = 26, 40, 92
    for i, (label, val) in enumerate(THROUGHPUT):
        y = top + i * (bar_h + gap)
        w = (val / vmax) * (bx1 - bx0)
        color = GREEN if "matching" in label else BLUE
        s.append(f'<text x="{bx0}" y="{y - 7}" fill="{TEXT}" font-size="12">{label}</text>')
        s.append(f'<rect x="{bx0}" y="{y}" width="{bx1 - bx0}" height="{bar_h}" rx="4" fill="{GRID}" opacity="0.35"/>')
        s.append(f'<rect x="{bx0}" y="{y}" width="{w:.1f}" height="{bar_h}" rx="4" fill="{color}"/>')
        s.append(
            f'<text x="{bx0 + w - 8:.1f}" y="{y + bar_h / 2 + 4:.1f}" fill="{BG}" '
            f'font-size="12" font-weight="600" text-anchor="end">{val / 1000:.0f}k</text>'
        )

    s.append("</svg>")

    out = os.path.normpath(OUT)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(s) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
