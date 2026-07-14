# Changelog

All notable changes to `null-sigma` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

Repository / packaging work since library **0.1.3** (crates.io / docs.rs).
**No library API bump yet** — `null-sigma` remains `0.1.3` on crates.io.

### Added

- **Week 1 trust sprint (harness).** `--on-error continue|fail-fast`, split
  flatten error taxonomy, `--max-line-bytes`, `--max-error-samples`, accounting
  invariant FATAL, hermetic fixtures (`tests/fixtures/robustness/`,
  `tests/fixtures/rules/minimal/`), `smoke_trust.sh` / `smoke_determinism.sh`,
  CI `trust-smoke` job for the harness.
- **`null-sigma-cli` (ROADMAP §4, Week 2 Days 1–3 + §4b MT).** Path-installable
  product CLI (`cli/`, version `0.1.0`, `publish = false`): file/stdin JSONL,
  lean NDJSON alerts, `--format text`, buffered/ordered stdout (§11.10–§11.11),
  trust stderr contract. Day 3 CI `cli-trust-smoke`. §4b: sequenced block-chunk
  Rayon pipeline with ordered sink + trust bags; `smoke_parallel.sh` ST↔MT
  parity. No product MT bake-off numbers until Linux hyperfine.

### Changed

- **Tier B baseline refresh (2026-07-13).** Hyperfine 100k events: null-sigma
  default-threads **7.26 s** (~13 780/s), **~2.14×** vs Hayabusa default
  (was 15.2 s / ~1.57× on 2026-07-08). README meter legend, `PERFORMANCE.md`
  §6c/§11.5/§11.9, harness README, ROADMAP, and `assets/tier_b.svg` updated.
  Prior baseline retained in prose for audit. No library API change.
- Tier B parallel runner + Hayabusa wall-clock wins first landed in
  `PERFORMANCE.md` §11.9 (harness-only; not a crates.io artifact).

---

## [0.1.3] — 2026-07-08

### Added

- **EventView value cache.** Lazily caches folded (lowercased) event field
  values and, for active-wildcard conditions only, a char vector of the folded
  string. Shared across all rules for one event evaluation — including
  `|fieldref`. Removes per-condition `to_lowercase` on event fields and avoids
  repeated `Vec<char>` allocation in `wildcard_match_impl`.

### Changed

- **Tier A performance (SigmaHQ 1 102 rules, benign event).** Single-event
  latency **314 µs → 309 µs** (~1.5–2% vs Phase 2). Batch ~373 ms (noise vs
  prior 378 ms).

---

## [0.1.2] — 2026-07-08

### Added

- **EvalScratch (Phase 2).** Thread-local reusable buffers for the AC hit bitmap
  and dense per-rule identifier results. Eliminates per-event `Vec<bool>` and
  per-rule `HashMap<String, bool>` allocation on the hot path. Exported as
  [`EvalScratch`](https://docs.rs/null-sigma/latest/null_sigma/struct.EvalScratch.html).

- **Load-time `ValueMatchCache` (Phase 2).** String match values are
  case-folded and pre-classified at rule load as unescaped literals or
  pre-tokenized wildcard patterns (`PatToken`). The matcher skips runtime
  `tokenize_pattern` on contains/startswith/endswith/exact paths. Transform
  modifiers (`|base64`, `|wide`, `|windash`) still expand at eval time.

- **Phase 2 regression tests.** Guards for `ac_hits` / `id_results` stale-state
  bleed across events and rules, and case-folding alignment for cached patterns.

### Changed

- **Tier A performance (SigmaHQ 1 102 rules, benign event).** Single-event
  latency **541 µs → 314 µs** (~42% faster, ~1.7× vs Phase 1). Gap vs
  tau-engine narrowed from ~3.9× to ~2.3×. Batch 1 000 events: **602 ms →
  378 ms**.

---

## [0.1.1] — 2026-07-07

### Fixed

- **AC prefilter false negatives on overlapping patterns.** `find_iter` is
  non-overlapping and reports only the lowest pattern ID when multiple patterns
  share the same match position. Duplicate pattern strings across rules could
  cause later rules' pattern indices to never be set. Fixed with
  `find_overlapping_iter` plus `ac_pattern_lookup` pattern interning.

- **AC prefilter false negatives on negated conditions.** The Aho-Corasick
  prefilter skipped rules whenever no string pattern hit — but for conditions
  like `condition: not selection`, an event with zero AC hits is exactly the
  event that should match. Prefilter eligibility now additionally requires
  that the compiled condition cannot fire with all identifiers false.

- **Per-identifier AC gating too coarse.** Rule-level `fully_ac_covered` gated
  the entire rule even when only some identifiers were AC-dependent. New
  `conditions_require_gated_hit()` enables per-identifier gating: 1 044/1 102
  real SigmaHQ `process_creation` rules are gated without false negatives.

- **Logsource hash-collision misrouting.** The hot loop compares logsource
  fields by 32-bit FNV-1a hash; a collision could evaluate a rule against the
  wrong log source. Rules passing the hash prefilter are now re-checked
  against the actual logsource strings before evaluation (cold path only —
  no hot-loop cost).

- **Sigma wildcard escaping.** Patterns are now tokenized per the Sigma spec:
  `\*` and `\?` are literal characters, `\\` is a single backslash, and a
  lone backslash before a normal character passes through unchanged
  (`\cmd.exe` needs no escaping). Previously every `*`/`?` acted as a
  wildcard with no way to match the literal characters. Escaped literals
  remain Aho-Corasick-eligible; the automaton stores the unescaped bytes.

- **`|base64offset` trailing trim.** Offset variants now trim the trailing
  characters (and `=` padding) whose bits depend on the bytes following the
  value, so values embedded mid-stream in longer base64 data are detected.
  Previously only values at the very end of the encoded data matched.

### Added

- **Head-to-head benchmark harness** (`harness/` workspace crate, roadmap
  item 3). Compares null-sigma, tau-engine (Chainsaw core), and sigma-rust on
  the same SigmaHQ rules and seeded events. Includes `cross_check` correctness
  gate, Tier A Criterion benches (`head_to_head`), Tier B hyperfine CLI
  comparison (`run_cli_bench.sh` vs Hayabusa 3.9.0 / Chainsaw 2.13.1),
  deterministic event generator, and `null_sigma_run` reference CLI.
  Documented in `harness/README.md` and `PERFORMANCE.md` §11.

- **EventView + fold-once matching (Phase 1).** New `fold.rs` and
  `event_view.rs` modules. `FieldCondition` gains `field_folded` and
  `values_folded` (populated at load time). `EventView::from_map()` builds a
  folded-key index once per event; the matcher uses pre-folded literals on the
  hot path. ~6× improvement on SigmaHQ `process_creation` workload (541 µs vs
  ~3.3 ms per benign event).

- **Count-only evaluation API.** `evaluate_event_count()` and
  `evaluate_json_count()` return match counts without building `RuleMatch`
  structs — used by the harness runner and Tier B benchmarks.

- **`json` feature — nested JSON telemetry ingestion.** Optional flattening
  layer (`serde_json` behind a feature flag; the core compiles identically
  with it off) that converts nested events (ECS, Sysmon, CloudTrail) into
  the engine's flat format: objects → dot paths, exact `i64`/`u64` rendering,
  `null` → empty (preserves Sigma `field: null` semantics), arrays → indexed
  keys plus a joined base key so `|contains` matches any element,
  deterministic first-write-wins collision policy, and typed-error guards
  (`max_depth` 64, `max_fields` 10 000) against adversarial documents.
  API: `SigmaEngine::evaluate_json`, `json::flatten_str` / `flatten_value`
  (+ `_with` variants). Tested by 29 unit/fixture tests, 4 new proptest
  properties, a new `fuzz_flatten_json` target, and dedicated benchmarks
  (ECS event: flatten 8.3 µs, evaluate_json 11.9 µs); CI runs the full
  matrix with and without the feature. Core suite verified regression-free
  (feature off by default — identical core binary; two full benchmark runs
  all within noise, see `PERFORMANCE.md` §10).

- **`|fieldref` modifier** (Sigma v2): compare a field against the value of
  another event field (`ParentImage|fieldref: Image` fires when a process
  executes itself). Composes with `contains`/`startswith`/`endswith`/`all`.
  Referenced values compare literally — wildcards in event data are not
  patterns. FieldRef conditions are excluded from the AC prefilter.

- **`|re` flag sub-modifiers** `i`/`m`/`s` (Sigma v2): `re|m` enables
  multi-line anchors, `re|s` enables dot-matches-newline; `re|i` is accepted
  as a no-op (the engine's `|re` is already case-insensitive by default).
  A bare flag without a preceding `|re` is a parse error.

- **SigmaHQ corpus compatibility harness** (`examples/corpus_report.rs`):
  loads the full official rule corpus and prints a categorized report.
  Result: **3 745 / 3 745 (100%)** of the active SigmaHQ rule sets load
  (`rules`, `rules-emerging-threats`, `rules-threat-hunting`,
  `rules-compliance`); the 17 `rules-placeholder` files using `|expand`
  are a documented exclusion (they require external placeholder catalogs).
  Bulk load of all 3 745 rules: ~270 ms.

- `EngineError::InvalidRegex` — a `|re` pattern that fails to compile now
  rejects the rule at load time instead of silently never matching. Failed
  loads leave the engine state untouched. `EngineError` is re-exported at the
  crate root.

- Regression tests for all of the above, including a brute-forced FNV-1a
  hash collision test (237 tests with `json` feature, up from 166 at 0.1.0).
  
- Benchmark chart in the README (`assets/benchmarks.svg`) showing rule-count
  scaling vs naive linear cost and per-scenario throughput, generated by the
  dependency-free `scripts/gen_benchmark_chart.py`.

### Changed

- **Benchmark numbers updated to measured head-to-head results.** Synthetic
  microbench (`1000_rules_single_event`): **311k events/sec** (was 427k).
  Real SigmaHQ `process_creation` (1 102 rules): **~1 850 events/sec** per
  benign event; tau-engine is ~3.9× faster on this workload. See
  `PERFORMANCE.md` §6 and §11; obsolete "3–5× faster than Hayabusa" claims
  removed.

- `|windash` expands to the full Sigma dash variant set — `-`, `/`,
  `–` (en dash), `—` (em dash), `―` (horizontal bar) — bidirectionally.
  Previously only `-` ↔ `/` were covered.

---

## [0.1.0] — 2026-07-02

### Added

- Full Sigma rule evaluation engine: YAML parse → condition AST compile → event match
- 15 Sigma value modifiers: `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`,
  `base64`, `base64offset`, `wide`, `windash`, `gt`, `gte`, `lt`, `lte`, `exists`
- Condition language: `and`, `or`, `not`, parentheses, `1 of selection*`,
  `all of them`, `N of (id1, id2, …)`
- `SigmaEngine` with Aho-Corasick batch prefilter and 24-byte hot/cold struct split
- Cache-friendly logsource prefilter using FNV-1a hashed integer comparisons
- Pre-compiled regex cache (`match_identifier_with_cache`) — compile once, match many
- Zero-allocation `enrich_event_cow` using `Cow<HashMap>` — no clone when event
  already uses Sigma field names
- `evaluate_event` / `evaluate_batch` take `&self` — thread-safe concurrent evaluation
- `FieldMapping` with pre-built reverse map for `O(n_event)` field enrichment
- Fuzz targets: `fuzz_parse_rule`, `fuzz_evaluate_event`
- 166 tests: unit, corpus replay, proptest property-based, concurrent correctness
- 10 Criterion benchmarks including logsource-mismatch and regex isolation paths
- `#![forbid(unsafe_code)]` — compiler-enforced, zero unsafe
- Apache-2.0 license
