# null-sigma — Roadmap

Strategic direction, in priority order. Ground rule for every item: **no or
minimal regression** — the full test suite must stay green and benchmarks must
stay within noise threshold after each change. One change at a time, gated.

Structural rule: the core crate stays exactly what it is — events in, matches
out, three dependencies, no I/O. New capabilities ship as separate workspace
crates that consume the core (`null-sigma-cli`, `null-sigma-json`,
`null-sigma-py`). File reading, JSON flattening, and output formatting must
never leak into `matcher.rs` / `engine.rs`.

---

## 1. SigmaHQ corpus compatibility (DONE — 2026-07-04)

Ran the full official [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) rule
corpus (3 762 files) through parse + load via `examples/corpus_report.rs`.

Findings and fixes:
- Initial run: 99.4% loaded. Gaps found: `|fieldref` (3 rules), `|re|i`
  regex flag (1 rule), `|expand` (17 rules, all in `rules-placeholder`).
- Implemented `|fieldref` and `|re` flag sub-modifiers (`i`/`m`/`s`) with
  13 new tests; full regression gate green, hot-path benchmarks within noise.
- Final: **3 745 / 3 745 (100%)** of active rule sets load. `|expand` is a
  documented exclusion — placeholder rules require external catalogs and are
  meant for pipeline preprocessing, not direct evaluation.

Possible follow-up: `|expand` support via a user-supplied placeholder map at
load time (would take placeholder rules from 0% to 100% too).

## 2. Nested JSON event ingestion

Real telemetry is nested JSON (ECS, Windows XML→JSON, CloudTrail); the API
takes `HashMap<String, String>`. Add a flattening layer
(`serde_json::Value` → dotted field paths) as a **separate module/crate**,
not woven into the matcher. This is the main real-world adoption blocker.

## 3. Head-to-head benchmark harness

Same machine, same rule set, same pre-parsed events vs Hayabusa and Chainsaw
matching paths; harness published in-repo. Converts the "4–5× faster"
projection into a measured fact (or an honest correction). Until then, keep
comparative claims labeled approximate.

## 4. CLI binary (`null-sigma-cli`)

Tail a JSON log file or read stdin, emit alerts. Demo-able artifact; ten
times more people run a demo than read API docs.

## 5. Reach multipliers (later)

- **Python bindings** via pyo3 — drop-in ~100× speedup for the pySigma
  community.
- **Sigma v2 correlation rules** (`event_count`, `temporal`) — almost no open
  engine does this well; genuine differentiator.

---

## Working agreements

- Full regression gate after every change: `cargo fmt --check`,
  `cargo clippy` (pedantic, zero warnings), `cargo test` (all green),
  benchmark spot-check within noise.
- Fail loud, never silent: any input we accept must either work per spec or
  return a typed error.
- Corpus fixtures and vendored rule sets are dev-only inputs — gitignored,
  never committed, never a runtime dependency.
