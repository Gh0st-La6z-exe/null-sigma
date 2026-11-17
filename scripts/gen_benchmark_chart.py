#!/usr/bin/env python3
"""Generate assets/benchmarks.svg from proven Tier A benchmarks and optimization progression.

Dependency-free (Python standard library only).
Reflects:
- Tier A Head-to-Head Latency (Criterion 99% bootstrap CI, 250 samples, SigmaHQ process_creation)
- Inverted Dispatch Matrix Optimization Descent (prof_benign 1,000-iteration wall latency)
- 11.1M-evaluation differential cross-check & 100% SigmaHQ coverage proof.
"""

from __future__ import annotations

import os

# ── Data (Verified Gold-Standard Baselines) ───────────────────────────────────

# Tier A Head-to-Head Latency (in ms for scale, lower is better)
HEAD_TO_HEAD = [
    ("sigma-rust (1,110 rules)", 12.016, "#f85149", "12.02 ms (1.0× baseline)"),
    ("null-sigma (1,193 rules, full)", 1.109, "#58a6ff", "1.11 ms (100% coverage)"),
    ("null-sigma (1,110 rules, common)", 0.962, "#3fb950", "961.5 µs (12.5× faster)"),
    ("tau-engine (1,110 rules only)", 0.492, "#d29922", "492.1 µs (93.0% coverage)"),
]

# Engine Optimization Progression (in µs, lower is better)
PROGRESSION = [
    ("Post-AC Inverted Dispatch Baseline", 3070.0, "#8b949e", "3,070 µs / event"),
    ("Phase 5 (+ Bloom & Canonical Slots)", 1166.7, "#58a6ff", "1,167 µs (-62.0%)"),
    ("Step 2 (+ Dense RuleBitSet Dispatch)", 950.6, "#3fb950", "951 µs (-69.1%)"),
    ("Step 3 Target (Flat Decision Tape)", 450.0, "#d29922", "< 450 µs (projected)"),
]

# ── Visual Style ─────────────────────────────────────────────────────────────

BG = "#0d1117"
CARD_BG = "#161b22"
GRID = "#30363d"
TEXT = "#f0f6fc"
TEXT_MUTED = "#8b949e"
BLUE = "#58a6ff"
GREEN = "#3fb950"
ORANGE = "#d29922"
RED = "#f85149"
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"

W, H = 920, 440
OUT = os.path.join(os.path.dirname(__file__), "..", "assets", "benchmarks.svg")


def main() -> None:
    s: list[str] = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="{FONT}">'
    )
    s.append(f'<rect width="{W}" height="{H}" rx="10" fill="{BG}" stroke="{GRID}" stroke-width="1"/>')

    # ── Header ───────────────────────────────────────────────────────────────
    s.append(
        f'<text x="{W / 2}" y="32" fill="{TEXT}" font-size="16" font-weight="700" '
        f'text-anchor="middle">null-sigma — Tier A Head-to-Head &amp; Optimization Descent</text>'
    )
    s.append(
        f'<text x="{W / 2}" y="52" fill="{TEXT_MUTED}" font-size="12" text-anchor="middle">'
        f'Official SigmaHQ process_creation corpus · Criterion 250 samples, 99% bootstrap CI (p &lt; 0.01)</text>'
    )

    # ── Left Panel: Tier A Head-to-Head Latency ──────────────────────────────
    lx0, lx1 = 45, 445
    ly0, ly1 = 75, 365
    s.append(
        f'<rect x="{lx0}" y="{ly0}" width="{lx1 - lx0}" height="{ly1 - ly0}" rx="8" '
        f'fill="{CARD_BG}" stroke="{GRID}" stroke-width="1"/>'
    )
    s.append(
        f'<text x="{lx0 + 16}" y="{ly0 + 26}" fill="{TEXT}" font-size="13" font-weight="600">'
        f'Tier A Matcher Latency (single_benign_event)</text>'
    )
    s.append(
        f'<text x="{lx0 + 16}" y="{ly0 + 42}" fill="{TEXT_MUTED}" font-size="11">'
        f'1,110 common rules · Criterion 99% CI · Lower is better</text>'
    )

    h2h_max = 13.0  # ms scale
    h2h_bx = lx0 + 16
    h2h_bw_max = (lx1 - lx0) - 32
    bar_h = 24
    row_gap = 46
    start_y = ly0 + 64

    for i, (label, val_ms, col, note) in enumerate(HEAD_TO_HEAD):
        y = start_y + i * row_gap
        bw = max(24.0, (val_ms / h2h_max) * h2h_bw_max)
        s.append(f'<text x="{h2h_bx}" y="{y - 5}" fill="{TEXT}" font-size="11" font-weight="500">{label}</text>')
        # Background bar
        s.append(f'<rect x="{h2h_bx}" y="{y}" width="{h2h_bw_max}" height="{bar_h}" rx="4" fill="{GRID}" opacity="0.35"/>')
        # Value bar
        s.append(f'<rect x="{h2h_bx}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="4" fill="{col}"/>')
        # Value text inside or beside bar
        if bw > 140:
            s.append(
                f'<text x="{h2h_bx + bw - 8:.1f}" y="{y + 16}" fill="#0d1117" '
                f'font-size="11" font-weight="700" text-anchor="end">{note}</text>'
            )
        else:
            s.append(
                f'<text x="{h2h_bx + bw + 8:.1f}" y="{y + 16}" fill="{TEXT}" '
                f'font-size="11" font-weight="600" text-anchor="start">{note}</text>'
            )

    # ── Right Panel: Optimization Progression ────────────────────────────────
    rx0, rx1 = 475, 875
    ry0, ry1 = 75, 365
    s.append(
        f'<rect x="{rx0}" y="{ry0}" width="{rx1 - rx0}" height="{ry1 - ry0}" rx="8" '
        f'fill="{CARD_BG}" stroke="{GRID}" stroke-width="1"/>'
    )
    s.append(
        f'<text x="{rx0 + 16}" y="{ry0 + 26}" fill="{TEXT}" font-size="13" font-weight="600">'
        f'Engine Optimization Descent (prof_benign)</text>'
    )
    s.append(
        f'<text x="{rx0 + 16}" y="{ry0 + 42}" fill="{TEXT_MUTED}" font-size="11">'
        f'Tight-loop wall latency per event · Lower is better</text>'
    )

    prog_max = 3300.0  # µs scale
    prog_bx = rx0 + 16
    prog_bw_max = (rx1 - rx0) - 32

    for i, (label, val_us, col, note) in enumerate(PROGRESSION):
        y = start_y + i * row_gap
        bw = max(24.0, (val_us / prog_max) * prog_bw_max)
        s.append(f'<text x="{prog_bx}" y="{y - 5}" fill="{TEXT}" font-size="11" font-weight="500">{label}</text>')
        # Background bar
        s.append(f'<rect x="{prog_bx}" y="{y}" width="{prog_bw_max}" height="{bar_h}" rx="4" fill="{GRID}" opacity="0.35"/>')
        # Value bar
        if "Target" in label:
            s.append(
                f'<rect x="{prog_bx}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="4" '
                f'fill="{col}" fill-opacity="0.3" stroke="{col}" stroke-width="1.5" stroke-dasharray="4 3"/>'
            )
            s.append(
                f'<text x="{prog_bx + bw + 8:.1f}" y="{y + 16}" fill="{col}" '
                f'font-size="11" font-weight="700" text-anchor="start">{note}</text>'
            )
        else:
            s.append(f'<rect x="{prog_bx}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="4" fill="{col}"/>')
            if bw > 140:
                s.append(
                    f'<text x="{prog_bx + bw - 8:.1f}" y="{y + 16}" fill="#0d1117" '
                    f'font-size="11" font-weight="700" text-anchor="end">{note}</text>'
                )
            else:
                s.append(
                    f'<text x="{prog_bx + bw + 8:.1f}" y="{y + 16}" fill="{TEXT}" '
                    f'font-size="11" font-weight="600" text-anchor="start">{note}</text>'
                )

    # ── Bottom Summary Banner ────────────────────────────────────────────────
    by = 380
    bh = 42
    s.append(
        f'<rect x="{lx0}" y="{by}" width="{rx1 - lx0}" height="{bh}" rx="6" '
        f'fill="{CARD_BG}" stroke="{GRID}" stroke-width="1"/>'
    )
    s.append(
        f'<text x="{lx0 + 20}" y="{by + 26}" fill="{GREEN}" font-size="12" font-weight="700">'
        f'✓ 11.1M Evaluations Cross-Check: 0.0000% Disagreement (4,132 / 4,132 hits vs sigma-rust)'
        f'</text>'
    )
    s.append(
        f'<text x="{rx1 - 20}" y="{by + 26}" fill="{BLUE}" font-size="12" font-weight="700" text-anchor="end">'
        f'✓ 100.0% SigmaHQ Coverage (1,193 / 1,193 rules in 153 ms)'
        f'</text>'
    )

    s.append("</svg>")

    out = os.path.normpath(OUT)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(s) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
