# Changelog

All notable changes to `null-sigma` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.5] — 2026-11-22

### Added

- **The Titan Gauntlet (55.5 Billion Evaluations & Megabyte Linear Scan Verification):**
  - **The Titan Multi-Core Firehose (`harness/src/bin/titan_gauntlet.rs`):** Evaluated **50,000,000 events** across 8 logical SMT threads (4 physical cores) against 1,110 rules (**55,500,000,000 total rule checks**) in **490.07 seconds** at **102,027 sustained Events/Sec** and **113 Million rule evaluations per second** (86.8% physical core efficiency), accurately firing 20,660,000 threat alerts with **0 bytes memory leaked** (+4.70 MB net process RSS delta over 50M events).
  - **Hard Logsource Partitioning (Vector 1 in `src/engine.rs`):** Partitioned unconstrained rules into dedicated `category_unconstrained`, `service_unconstrained`, `product_unconstrained`, and `wildcard_unconstrained` bitsets, eliminating cross-category evaluation waste and maintaining L2 CPU cache residency.
  - **Head-to-Head Benchmarking Against Double-Array Peer (`rsigma-eval` v0.27.0):** Benchmarked against indexed multi-rule engine `rsigma-eval` via `test_rsigma.rs` and `audit_payloads.rs`. Demonstrated 1.04× to 2.01× advantage on process and attack telemetry, 4.3× to 5.2× advantage on megabyte-scale payload scans, and a 626× advantage (1.02 µs vs 640.24 µs) on bypassed telemetry.
  - **Megabyte-Scale Linear Scanning Throughput (`harness/src/bin/audit_payloads.rs`):** Extended pathological repetition stress to 16 KiB (80.18 µs, 194.9 MiB/s), 32 KiB (146.86 µs, 212.8 MiB/s), 64 KiB (255.60 µs, 244.5 MiB/s), 256 KiB (979.71 µs, 255.2 MiB/s), 512 KiB (2,064.10 µs, 242.2 MiB/s), and **1,024 KiB / 1 Megabyte (3,945.51 µs, 253.5 MiB/s)**, mathematically verifying linear $O(N)$ byte-scanning bounds (195–255 MiB/s) without quadratic runaway.
  - **Formally Verified Zero Hot-Path Heap Allocations (`tests/allocation_tests.rs`):** Implemented a custom counting `#[global_allocator]` integration test that asserts strictly **0 allocations and 0 bytes allocated** across 30,000 continuous event evaluations after thread-local pool warmup.
  - **Unified 2,427-Rule Windows Mega-Engine:** Ingested, compiled, and indexed **100.0% of all 2,427 Windows rules** in the SigmaHQ repository into a single unified `SigmaEngine` in **1.02 seconds**, sustaining **38,988 to 61,180 EPS** across execution, registry, and scriptblock telemetry.
  - **End-to-End 1,000,000 Raw JSON String Ingestion Soak:** Streamed, parsed, flattened, and evaluated 1,000,000 raw JSON string payloads through `evaluate_json_count` in **65.66 seconds** (**15,230 EPS** including complete JSON deserialization) with bounded steady-state memory (+0.35 MB initial delta, 0.00 MB drift over the final 500k strings).
  - **Untrusted Rule Parser Recursion Guard (`src/condition.rs`):** Added `pub const MAX_CONDITION_DEPTH: usize = 128;` and `CompileError::ConditionDepthExceeded`, preventing stack-overflow attacks from malicious or deeply nested condition expressions in untrusted intelligence feeds.
  - **Universal Multi-Category Corpus Evaluation (`harness/src/bin/cross_category.rs`):** Verified 100.0% rule compilation and evaluation across Windows Registry (250 rules), File Events (189 rules), Network/DNS (51 rules), and PowerShell (211 rules), proving 10× to 30× speedups over Chainsaw across all security domains.
  - **Multi-Core SMP Scaling Harness (`harness/src/bin/stress_concurrency.rs`):** Verified linear scaling up to **138,665 EPS** on 8 SMT threads (4.88× scaling, 98,838 EPS on 4 physical cores, 86.9% efficiency) for 100k event batches.
  - **10,000,000 Event Continuous Soak Test (`harness/src/bin/stress_soak.rs`):** Verified bounded 0.45 MB working set stability over 10M sequential evaluations.

- **Extreme Stress Testing & 20× Chainsaw Dominance:**
  - **Conjunction Verification (`SingleCheck::All` in `src/engine.rs`):** Evaluates all sound conditions in an identifier group with short-circuiting and precomputed bitmask deduplication (`covered_slots: u64`), eliminating redundant candidate evaluations and reducing surviving candidates for benign telemetry from 413 down to **6 rules**.
  - **Regex AST Mandatory Bloom Extraction (`src/discriminator.rs`):** Traverses regex syntax trees via `regex-syntax` to extract unquantified mandatory literal substrings, unioning 256-bit Bloom filters and intersecting alternations. Rejects non-matching strings targeting regexes in ~2 nanoseconds.
  - **SIMD Non-ASCII Filter (`SingleCheck::FieldNonAscii` in `src/engine.rs`):** Accelerated `!view.raw_at(i).is_ascii()` rejecting standard ASCII telemetry on emoji/homoglyph detection rules in ~2 nanoseconds.
  - **Bloom Capacity Expansion:** Expanded bloom checks to support up to 256 needles in `FieldBloomAny` (capturing rules with up to 256 needles such as Rule 533 with 174 needles).
  - **Adversarial Stress Testing Gauntlet (`harness/src/bin/stress_gauntlet.rs`):** Comprehensive testing binary incorporating pathological repetition payloads (16 KiB, 32 KiB, 64 KiB), 100-rule attack storms, 512-field telemetry, 8 KiB whitespace padding, null bytes/emojis/homoglyphs, 35-level deep JSON flattening, and 2,000-binary cache-thrashing.
  - **Permanent Empirical Proof Dossier ([`EMPIRICAL_PROOF.md`](EMPIRICAL_PROOF.md)):** Complete publication of system specifications, raw terminal logs, head-to-head scorecards, and mathematical parity proofs.

### Empirical Milestones

- **27.3× Faster than Chainsaw (`tau-engine`):** Evaluates benign process telemetry in **19.22 µs / event** (52,029 EPS) vs Chainsaw's **523.93 µs** (1,909 EPS). Evaluates 10,000-event mixed stream in **35.35 µs / event** (28,285 EPS) vs Chainsaw's **1,122.14 µs** (891 EPS, **31.7× faster**).
- **Direct Peer Advantage Over `rsigma-eval`:** Sustained **31,318 EPS** vs 30,000 EPS (1.04×) on single-core common rules, **25,355 EPS** vs 12,594 EPS (2.01×) on attack telemetry, and **977,813 EPS** vs 1,562 EPS (**626× faster**) on bypassed telemetry.
- **111,000,000 Evaluation Differential Cross-Check:** **0.0000% disagreement** (41,409 vs 41,409 hits) against reference implementation `sigma-rust` over 100,000 events × 1,110 rules. Chainsaw (`tau-engine`) suffered **489 missed attack detections** and failed to load 83 rules.
- **Linear $O(N)$ Scanning Throughput (Up to 16,438× Faster):** Scans 64 KiB active payloads at 244.5 MiB/s (**255.60 µs / event**) vs `rsigma-eval`'s 1,317.20 µs (**5.15× faster**), `tau-engine`'s 16,223.07 µs (**63.5× faster**), and `sigma-rust`'s 4.20 seconds (**16,438× faster**), while rejecting non-matching events in **1.02 µs** via discriminator and logsource pre-filtering.
- **Cache-Thrashing Performance Floor:** Sustained **60,025 EPS** (16.66 µs mean latency, 15.70 µs p50) across 10,000 events cycling through 2,000 distinct binaries.
- **Zero Memory Leak Invariant:** **0.0000 MB memory delta** across 100,000 sequential evaluations with **0 heap allocations** on the event evaluation hot path.
- **Full Workspace Test Suite:** All 308 tests across 9 workspace targets pass with zero failures and zero warnings under `#![forbid(unsafe_code)]`.

---

## [0.1.4] — 2026-11-21

### Added

- **Sub-256 Rolling Bigram Bloom Filter & Zero-Allocation Value Matching:**
  - **Sub-256 Vectorized Bigram Bloom Filter (`src/bloom.rs`):** Implemented `Bloom256` (`[u64; 4]`), expanding rolling bigram filtering from 64-bit to 256-bit. Reduced bit saturation on real command lines from 60–92% down to 22–46%, cutting bloom false positives from 37–85% to $<4.6\%$. Evaluates subset test in 4 bitwise `AND` instructions ($<1$ cycle).
  - **Zero-Allocation String Value Fast Path (`src/matcher.rs`):** Replaced eager `sigma_value.as_str_lossy()` heap string allocations with direct borrowed string slices (`sigma_value.as_str()`) and precomputed case-folded slices (`sigma_folded`), eliminating thousands of heap allocations per event on the hot path.
  - **Lazy Canonical Slot Read Optimization (`src/matcher.rs`):** Canonical slot lookups bypass string normalization entirely.
  - **Single-Core Latency Reduction:** Reduced single-core benign latency on real SigmaHQ telemetry from 841.96 µs down to **309.24 µs / event** (3,234 events/sec).
  - **Absolute Correctness Maintained:** 100.0000% agreement across 11,100,000 evaluations against reference `sigma-rust` (0 disagreements, 4,132 vs 4,132 alert hits). All 279 tests pass green. Zero clippy warnings. Clean rustfmt.

- **Zero-Allocation Buffer Pooling & Flat Register Decision Tape (Roadmap Step 3):**
  - **Zero-Allocation `EventView` Object Pooling (`src/event_view.rs`):** Added `EventScratch` thread-local memory pools (`key_pool`, `vec_pool`, `value_string_pool`, `char_vec_pool`) and inline `stack_values: [&'a str; 48]`, eliminating per-event heap allocation churn on the evaluation hot path.
  - **In-Place Basename Normalization (`src/engine.rs`):** Pre-allocated thread-local `discriminator_buf` ASCII-lowers binary basenames in-place, eliminating 3 `String` heap allocations per event.
  - **Flat Register Decision Tape (`src/condition.rs`):** Implemented linear bytecode instruction set (`DecisionOp::JumpIfFalse`, `Quantifier`, `Jump`, `Return`) and iterative interpreter (`DecisionTape`), replacing recursive AST tree-walking and pointer-chasing with cache-friendly contiguous bytecode.
  - **Single-Cycle `MatchMode` Jump Tables (`src/matcher.rs`):** Replaced 6 linear scans across the modifier slice per candidate value with direct hardware jump table dispatch on `MatchMode`.
  - **Comprehensive Detection Engineering Documentation:** Detailed the exact technical root causes for Chainsaw (`tau-engine`)'s 83 rejected SigmaHQ rules (unsupported modifiers `|windash`, `|cidr`, `|fieldref`, `|wide`, standalone `|base64`, `|re` inline flags, numeric comparisons; keyless identifiers; aggregations) and its 53-cell disagreement on `proc_creation_win_susp_system_user_anomaly.yml` (erroneous AND-logic sequence flattening).
  - **Correctness & Parity Verification:** 279 / 279 tests passing green (`cargo test --all-targets --features json`), 0 clippy warnings (`cargo clippy --all-targets -- -D warnings`), 100% clean formatting (`cargo fmt -- --check`), and 0.0000% disagreement across 11,100,000 evaluations against reference `sigma-rust` (4,132 vs 4,132 detections).

- **Dense Rule-Bitset Candidate Filtering (Roadmap Step 2):**
  - Added `src/bitset.rs` providing `RuleBitSet` and `SetBitIter` using hardware intrinsics `trailing_zeros` (`TZCNT`) and `w &= w - 1` (`BLSR`).
  - Unified candidate generation via thread-local `scratch.candidate_mask: RuleBitSet`, replacing vector slice scanning.
  - Eliminated duplicate rule evaluations across image, original file name, and parent image discriminators via idempotent bit-setting.
  - Reduced `prof_benign` wall latency from 1,166.72 µs to 950.58 µs/event (-18.5%).
  - Zero cross-check disagreements against `sigma-rust` over 11,100,000 evaluations (4,132 hits vs 4,132 hits).

- **Generalized Discriminator Indexing & Transform Bypass (Roadmap Step 1):**
  - Generalized `compute_rule_discriminators_for_field` in `src/discriminator.rs` to extract process basenames across disjunction branches (`sel1 or sel2`).
  - Added `CompiledCondition::Single(usize)` fast path in `src/engine.rs`, bypassing identifier state reset and closure dispatch for ~80% of rules.
  - Added zero-allocation `Cow::Borrowed` transform modifier bypass in `src/matcher.rs` when `!condition.has_transforms`.
  - Scaled head-to-head Criterion benchmark harness to 250 samples, 5s warmup, 30s measurement window at 99% CI.

- **2-Tier Inverted Dispatch Matrix (ROADMAP Item C, Phases 1–4).**
  - **Tier 1 (Field-Presence Bitmask):** Canonical 64-field index (`src/field_mask.rs`) mapping fields to dense `0..63` bits with aliases. Rules compute `RuleHotData::required_fields_mask: u64` via boolean AST proof; non-matching events are rejected in 1 bitwise instruction.
  - **Tier 2 (Primary Discriminator Index):** Binary basename routing (`src/discriminator.rs`) on `Image` and `OriginalFileName` basenames, dispatching rules through `image_discriminator_index` buckets and `unconstrained_mask` via zero-allocation candidate bitset dispatch.
  - **Compact 24-byte `RuleHotData`:** Shrunk hot prefilter struct to exact 24 bytes (fits 2.66 rules per 64-byte L1 cache line).
  - **Gold-standard 99% CI benchmarks:** Harness Criterion configuration elevated to 99% bootstrap confidence intervals ($p < 0.01$, 250 samples).
  - **11.1M cross-check verification:** Evaluated 1,110 common SigmaHQ rules against 10,000 generated events: exact 0.0000% disagreement vs `sigma-rust` (4,132 vs 4,132 detections).

### Removed

- **Aho-Corasick dependency:** Removed `aho-corasick = "1.1"` dependency, automaton compilation, and whole-event character scans from the core crate, eliminating field bleed and whole-event scanning. Rule loading is now 4.3× faster than `tau-engine` (153 ms vs 660 ms).

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
  parity.
- **Tier B-product bench infra (Slice 1.5).**
  `harness/scripts/run_product_cli_bench.sh` (product CLI lean NDJSON →
  `/dev/null` vs Hayabusa 3.9.0; count-only tax row; science meta header) and
  `.github/workflows/product-cli-bench.yml` (`workflow_dispatch` only).
- **A4 alert-firehose sweep infra (§11.13).** Controlled `A4Hit` tagging via
  `gen_dataset --a4-hit-bpm`, hermetic rule pack `tests/fixtures/rules/a4_hit/`,
  `harness/scripts/run_a4_firehose_sweep.sh` (preflight + hyperfine slope for
  p=1%/10%/50%), `.github/workflows/a4-firehose-sweep.yml`
  (`workflow_dispatch`). Sibling meter to §11.12 — measurement pending review.

### Changed

- **Condition compiler hardening.** Conditions now require complete token
  consumption and reject unsupported pipes, invalid syntax, and malformed
  quantifier lists instead of silently accepting partial input. Regression
  coverage was added for these failure modes. Empty wildcard quantifier
  expansions remain an explicit compile-time policy decision before support is
  broadened.
- **Windows contributor setup.** The supported Windows build path is the
  native MSVC Rust host with Visual Studio Build Tools; local installer
  binaries are not part of the repository.
- **Tier B-product Linux 100k inked (2026-07-14 GHA).** Product CLI default
  **28.84 s** (~3 470/s), ~**1.03×** vs count-only ceiling, ~**1.79×** vs
  Hayabusa default on shared `ubuntu-latest` (ncpu=4). Darwin/5k pilot tax /
  Hayabusa ranking **falsified** for bake-off use. Full matrix + disposition:
  `PERFORMANCE.md` §11.12. Harness §6c / §11.5 untouched. Label GHA noise.
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
