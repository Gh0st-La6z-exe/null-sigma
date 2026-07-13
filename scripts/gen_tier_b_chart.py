#!/usr/bin/env python3
"""Generate assets/tier_b.svg from the latest Tier B hyperfine results.

Dependency-free (stdlib only). To refresh after running:

    cd harness
    ./scripts/run_cli_bench.sh

Then update the numbers in TIER_B below from `harness/data/tier_b_results.md` and run:

    python3 scripts/gen_tier_b_chart.py
"""

from __future__ import annotations

import os

# ── Data (Apple M4, 100k events, hyperfine 5 runs, 2026-07-13) ───────────────
#
# Source: `harness/data/tier_b_results.md` (local harness output; gitignored).
# Prior published baseline (2026-07-08): default-threads 15.246s / ~1.57× vs Hayabusa.
TIER_B = [
    ("null-sigma (threads=0)", 7.257),
    ("null-sigma (threads=4)", 11.502),
    ("hayabusa (default)", 15.534),
    ("chainsaw (rosetta)", 28.370),
    ("null-sigma (threads=1)", 36.616),
    ("hayabusa (threads=1)", 54.403),
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

W, H = 920, 360
OUT = os.path.join(os.path.dirname(__file__), "..", "assets", "tier_b.svg")


def esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def main() -> None:
    max_s = max(v for _, v in TIER_B)

    # Layout
    left = 240
    right = 40
    top = 70
    row_h = 42
    bar_h = 18
    chart_w = W - left - right

    def bar_w(s: float) -> float:
        return chart_w * (s / max_s)

    def color(label: str) -> str:
        l = label.lower()
        if l.startswith("null-sigma"):
            return GREEN
        if l.startswith("hayabusa"):
            return BLUE
        return ORANGE

    s: list[str] = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="{FONT}">'
    )
    s.append(f'<rect width="{W}" height="{H}" rx="10" fill="{BG}"/>')
    s.append(
        f'<text x="{W/2}" y="30" fill="{TEXT}" font-size="16" font-weight="600" '
        f'text-anchor="middle">Tier B wall-clock (100k events, Apple M4, hyperfine)</text>'
    )
    s.append(
        f'<text x="{W/2}" y="52" fill="{MUTED}" font-size="12" text-anchor="middle">'
        f'Lower is better · 2026-07-13 · Source: harness/data/tier_b_results.md</text>'
    )

    # Gridlines (every 10s)
    for t in range(10, int(max_s // 10 + 1) * 10 + 1, 10):
        x = left + bar_w(float(t))
        s.append(f'<line x1="{x:.1f}" y1="{top-10}" x2="{x:.1f}" y2="{H-24}" stroke="{GRID}" stroke-width="1"/>')
        s.append(
            f'<text x="{x:.1f}" y="{H-8}" fill="{MUTED}" font-size="11" text-anchor="middle">{t}s</text>'
        )

    # Rows
    for i, (label, secs) in enumerate(TIER_B):
        y = top + i * row_h
        s.append(
            f'<text x="{left-12}" y="{y+bar_h}" fill="{TEXT}" font-size="12" '
            f'text-anchor="end">{esc(label)}</text>'
        )
        w = bar_w(secs)
        s.append(f'<rect x="{left}" y="{y}" width="{w:.1f}" height="{bar_h}" rx="6" fill="{color(label)}"/>')
        s.append(
            f'<text x="{left+w+8:.1f}" y="{y+bar_h-3}" fill="{TEXT}" font-size="12" '
            f'text-anchor="start">{secs:.3f}s</text>'
        )

    s.append("</svg>")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(s) + "\n")

    print(OUT)


if __name__ == "__main__":
    main()

