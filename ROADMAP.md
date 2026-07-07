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

## 2. Nested JSON event ingestion (DONE — 2026-07-04)

Shipped as the feature-gated `json` module (decision: cargo feature over a
workspace crate — one crate on crates.io, `serde_json` optional, zero core
changes; the layering rule held: `matcher.rs`/`engine.rs` untouched).

Delivered: dot-path flattening, exact numeric rendering, null→empty (Sigma
`field: null` works), array semantics (indexed keys + joined base key for
any-element `|contains`), deterministic collision policy, depth/field guards
with typed errors, `SigmaEngine::evaluate_json`. Test stack: 29 unit/fixture
tests (ECS, Sysmon, CloudTrail), 4 proptest properties, `fuzz_flatten_json`
target, benchmarks (flatten 8.3 µs, evaluate_json 11.9 µs on a 30-field ECS
event), CI matrix with/without the feature.

Regression verification: the feature is off by default, so `cargo bench`
compiles the identical core binary — zero impact by construction. Confirmed
empirically with two full-suite runs (all 10 benchmarks within noise; details
in `PERFORMANCE.md` §10, including a recorded lesson that
`100_regex_rules_single_event` has ~6% run-to-run jitter and single-run
verdicts on it are not signal).

## 3. Head-to-head benchmark harness (DONE — 2026-07-07)

Shipped as standalone `harness/` workspace crate. Compares null-sigma,
tau-engine (Chainsaw matching core via faithful converter), and sigma-rust on
the same SigmaHQ `process_creation` rules and seeded event stream.

Delivered:
- **Correctness gate** — `cross_check` binary: 2.2M rule×event cells; 0
  disagreements vs sigma-rust; 13 cells (0.0006%) vs tau-engine (one rule,
  converter semantics).
- **Tier A** — Criterion matcher-level benches (`head_to_head`); 1 102 common
  rules, pre-built native event representations.
- **Tier B** — hyperfine CLI wall-clock vs pinned Hayabusa 3.9.0 and Chainsaw
  2.13.1 (`run_cli_bench.sh`); 100k JSONL events.
- Deterministic event generator (`gen.rs`, seed 42), Chainsaw JSON mapping fix
  (`config/chainsaw-json-mapping.yml`), `null_sigma_run` reference CLI.

Measured (Apple M4, release, 2026-07-07):
- Tier A single benign event: null-sigma **541 µs**, tau-engine **139 µs**,
  sigma-rust 4.61 ms.
- Tier B (100k events): Hayabusa default **17.7 s**, null-sigma runner 120.4 s.

Core fixes discovered/enabled by the harness:
- AC overlapping scan + pattern interning (false-negative elimination).
- Per-identifier AC gating (`conditions_require_gated_hit`).
- Phase 1 EventView + fold-once matching (~6× on real corpus).
- Count-only API (`evaluate_event_count`).

Full numbers and reproduction steps: `harness/README.md`, `PERFORMANCE.md` §11,
`harness/data/tier_b_results.md`.

Follow-up: Phase 2 (`EvalScratch` buffer reuse) and Phase 3 (ingest streaming,
optional rayon) — see `PERFORMANCE.md` §11.6.
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
