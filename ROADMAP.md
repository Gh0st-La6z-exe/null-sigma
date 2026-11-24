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

Measured (Historical 2026-07 baseline on legacy AC engine — superseded by Inverted Dispatch Matrix in §4):
- Tier A single benign event: null-sigma 309 µs (legacy), tau-engine 136 µs, sigma-rust 4.61 ms.
- Tier B hyperfine (100k events, Rayon):
  null-sigma default threads **7.26 s** (~13 780/s), Hayabusa default **15.5 s**,
  null-sigma ST **36.6 s**, Hayabusa ST **54.4 s**. **Wins ST (~1.49×) and
  MT (~2.14×)** vs Hayabusa. (Prior 2026-07-08: 15.2 s / ~1.57× MT.)
  Tax split (2026-07-08 measurement): eval **99%**.

Core fixes discovered/enabled by the harness:
- AC overlapping scan + pattern interning (false-negative elimination).
- Per-identifier AC gating (`conditions_require_gated_hit`).
- Phase 1 EventView + fold-once matching (~6× on real corpus).
- Phase 2 EvalScratch + load-time `ValueMatchCache` (~1.7× on top of Phase 1).
- EventView value cache (lazy fold + wildcard char cache; ~1.5–2% on top).
- Count-only API (`evaluate_event_count`).
- Tier B tax split + refreshed hyperfine baseline (no phantom 120 s).
- Rayon parallel Tier B runner (`--threads`) — beats Hayabusa default wall.

Full numbers and reproduction steps: `harness/README.md`, `PERFORMANCE.md` §11,
`harness/data/tier_b_results.md`.

Follow-up: matcher structural gap vs tau-engine remains open for Tier A.
Week 1 trust (§3e) DONE. §4 CLI Days 1–3 + sequenced MT slice shipped;
`--follow` / crates.io publish still open. Linux product 100k **inked** in
§11.12 (GHA noisy; dedicated metal may supersede).

## 3b. Phase 2 — EvalScratch + pattern cache (DONE — 2026-07-07)

Profiling gate on Tier A (`prof_benign`) identified allocator churn and
repeated wildcard tokenization as top hotspots. Shipped in two coupled changes:

- **`EvalScratch`** — thread-local reuse of `ac_hits` and dense `id_results`;
  `fill(false)` reset per event / per rule; `ConditionNode::evaluate_vec`.
- **`ValueMatchCache`** — load-time literal / pre-tokenized wildcard patterns
  built from `fold_value` (case-folding aligned with runtime); matcher fast path
  skips `tokenize_pattern` on hot comparisons.

Measured: **541 µs → 314 µs** per benign event (1 102 SigmaHQ rules); tau-engine
gap **3.9× → 2.3×**. Four regression tests guard stale-state bleed and
case-folding alignment. Documented in `PERFORMANCE.md` §11.7.

## 3c. EventView value cache (DONE — 2026-07-08)

Lazy per-field fold + optional char-vector caches on `EventView`, shared across
all rules for one event. Char cache gates on active wildcards only (Windows `\`
paths do not force it). `|fieldref` uses the same folded slots.

Measured: **314 µs → 309 µs** on Tier A benign; `cross_check` unchanged.
Documented in `PERFORMANCE.md` §11.8.

## 3d. Parallel Tier B runner (DONE — 2026-07-08)

Rayon `--threads` on harness `null_sigma_run`: sequential ingest, parallel
`evaluate_event_count` via `Arc<SigmaEngine>` (thread-local `EvalScratch` per
worker). Parity smoke at 1/2/4/8/0 threads on 10k events.

Measured (Tier B hyperfine, 100k events, **2026-07-13**): null-sigma default
threads **7.26 s** vs Hayabusa default **15.5 s** (~2.14× wall-clock win).
Single-thread still wins vs Hayabusa-1-thread (36.6 s vs 54.4 s, ~1.49×).
Prior 2026-07-08 baseline: 15.2 s / ~1.57× MT. Documented in `PERFORMANCE.md`
§11.5 / §11.9; chart: `assets/tier_b.svg`.

## 3e. Week 1 trust sprint (DONE — 2026-07-12)

Production-credibility gate for `null_sigma_run` (precursor to §4): never crash
on bad JSONL; deterministic ingest accounting; CI-enforced.

Delivered across Days 1–5:

- **Day 1** — `--on-error continue|fail-fast`, exit-code policy, base error counters
- **Day 2** — split flatten taxonomy, `--max-line-bytes`, startup hardening,
  robustness fixtures under `tests/fixtures/robustness/`
- **Day 3** — stderr contract, `--max-error-samples`, `smoke_determinism.sh`,
  loud accounting invariant (FATAL + exit 1)
- **Day 4** — hermetic minimal rules (`tests/fixtures/rules/minimal/`),
  `smoke_trust.sh`, `harness/tests/runner_trust.rs` (no SigmaHQ required)
- **Day 5** — CI job `trust-smoke` runs `cargo test` + `smoke_trust.sh` on
  every push/PR to `main`

Stderr contract and exit codes: `harness/README.md`. Synthetic fixtures under
`tests/fixtures/` are committed CI inputs — distinct from the gitignored
SigmaHQ corpus (still never vendored).

§4 may now proceed on a CI-gated ingest trust layer.

## 4. CLI binary (`null-sigma-cli`) — Days 1–3 + MT slice DONE (2026-07); follow/publish open

Product CLI crate at [`cli/`](cli/) — sibling package, `publish = false` until
crates.io release. Depends on `null-sigma` with the `json` feature. Core
library stays I/O-free.

**Shipped (Week 2 Days 1–3 + §4b sequenced MT):**

- Day 1 — trust-parity ingest: file + stdin JSONL, Week 1 exit/stderr contract
- Day 2 — lean NDJSON alerts + `--format text`, buffered stdout (§11.10)
- Day 3 — CI job `cli-trust-smoke` (hermetic fixtures + `mktemp` cleanup)
- §4b MT — sequential byte chunker (grow / `--max-line-bytes`), Rayon workers
  (local alert `Vec<u8>` + `ChunkTrustMetrics`), ordered sink by `ChunkID`,
  `--threads N|0` honored; ST and MT share one pipeline;
  `cli/scripts/smoke_parallel.sh` in CI (byte-identical NDJSON + trust parity)

**Install (local path today):**

```bash
cargo install --path cli
null-sigma-cli --rules ./rules --threads 0 < events.jsonl
```

**Slice 1.5 (DONE — infra + GHA 100k ink):** Tier B-product hyperfine —
`harness/scripts/run_product_cli_bench.sh` + GHA `Product CLI bench`
(`workflow_dispatch`). Linux 100k matrix and pilot disposition in
`PERFORMANCE.md` §11.12 (label GHA noise). Harness Tier B stays a separate meter.

**Not yet:** `--follow`, crates.io publish, dedicated-Linux recheck of §11.12.

**Next gate — A4 alert-firehose sweep (§11.13):** controlled event-hit rate
\(p \in \{1\%,10\%,50\%\}\), \(m \approx 1\), dual metrics (product **tax** vs
count-only, **Falcon** vs Hayabusa). Protocol + script:
`harness/scripts/run_a4_firehose_sweep.sh`. Sibling meter to §11.12 — do not
merge. Gates decide publish confidence (B1) vs emit/sink work.

**Active Architecture Milestone — Inverted Dispatch Matrix (ROADMAP Item C):**

- **Phases 1–4 (DONE):** Replaced monolithic Aho-Corasick prefilter with a 2-Tier Inverted Dispatch Matrix:
  - Tier 1: Canonical 64-bit Field-Presence Bitmask (`src/field_mask.rs`).
  - Tier 2: Primary Discriminator Index on process binary basenames (`src/discriminator.rs`).
  - Shrunk `RuleHotData` to exact 24 bytes (fits 2.66 rules per L1 cache line).
  - Rule compilation is **4.3× faster** than `tau-engine` (153 ms vs 660 ms).
- **Phase 5 (Parity — DONE):** Sub-64 rolling bigram Substring Bloom Filter (`src/bloom.rs`), dense canonical slots (`[u32; 64]`), secondary `ParentImage` discriminator, cost-ranked AST reordering, and zero-allocation `FieldInputs`.
- **Phase 6 / Steps 1–2 (DONE):**
  - Generalized discriminator indexing across multi-branch disjunctions (`sel1 or sel2`).
  - `CompiledCondition::Single` fast path bypassing identifier state resets.
  - Zero-allocation `Cow::Borrowed` transform modifier bypass in `src/matcher.rs`.
  - Dense `RuleBitSet` candidate dispatch (`src/bitset.rs`) using CPU `TZCNT` and `BLSR` intrinsics, eliminating duplicate rule evaluations across buckets in $<2.5$ L1 cachelines.
  - Latency reduced to **961.50 µs** (Criterion 99% CI) / **950.58 µs / event** (`prof_benign`), with **0.0000% disagreement** against `sigma-rust` over 11,100,000 evaluations (4,132 vs 4,132 hits).
- **Step 3 (DONE — 2026-11):**
  - Zero-Allocation `EventView` buffer pooling with `EventScratch` thread-local object pools (`key_pool`, `vec_pool`, `value_string_pool`, `char_vec_pool`) and inline `stack_values` (capacity 48).
  - In-place ASCII basename normalization buffer, eliminating per-event heap allocations.
  - Flat Register Decision Tape (`src/condition.rs`) linear bytecode engine (`JumpIfFalse`, `Quantifier`, `Jump`, `Return`), replacing recursive AST tree-walking with single-cacheline bytecode evaluation.
  - Single-cycle `MatchMode` jump table dispatch in `src/matcher.rs`, eliminating 6 linear modifier slice scans per value.
  - Verified 100% green: 279 tests passing, 0 clippy warnings, 0.0000% disagreement across 11,100,000 evaluations against reference `sigma-rust` (4,132 vs 4,132 hits). Detailed security engineering documentation added for Chainsaw's 83 rejected rules and 53-cell discrepancy on `proc_creation_win_susp_system_user_anomaly.yml`.
- **Step 4 (DONE — 2026-11): Sub-256 Vectorized Bloom & Zero-Allocation Value Matcher:**
  - Sub-256 vectorized rolling bigram bloom filter in `src/bloom.rs`, expanding bitset to 256-bit (`[u64; 4]`), cutting bit saturation to 22–46% and false positives to $<4.6\%$.
  - Zero-allocation string value comparison path in `src/matcher.rs`, replacing eager `as_str_lossy()` allocations with borrowed slices (`as_str()`) and precomputed folded slices (`sigma_folded`).
  - Ingest latency reduced to **309.24 µs / event** (3,234 vs 2,181 events/sec on `prof_benign`).
  - Absolute soundness: 100.0000% agreement over 11,100,000 evaluations vs reference `sigma-rust` (4,132 vs 4,132 alert fires). All 279 tests green, 0 clippy warnings, clean rustfmt.
- **Step 5 (DONE — 2026-11): Conjunction Verification, AST Mandatory Bloom & Titan Gauntlet:**
  - `SingleCheck::All` conjunction verification with bitmask deduplication (`covered_slots: u64`), cutting candidate evaluations for benign process telemetry to 6 rules.
  - Regex AST mandatory literal extraction (`regex-syntax`), populating 256-bit Bloom filters and rejecting non-matching strings in ~2 ns.
  - Evaluated **50,000,000 events** across 8 SMT threads against 1,110 rules (**55,500,000,000 rule checks**) in 490.07 s at **102,027 sustained EPS** with 0 bytes memory leaked.
  - Reduced single-core benign latency to **19.22 µs / event** (52,029 EPS) and mixed stream to **35.35 µs / event** (28,285 EPS).
- **Step 6 (DONE — 2026-11): Hard Logsource Partitioning (Vector 1) & `rsigma-eval` Peer Benchmarking:**
  - Partitioned unconstrained rules into dedicated `category_unconstrained`, `service_unconstrained`, `product_unconstrained`, and `wildcard_unconstrained` bitsets in `src/engine.rs`, eliminating cross-category evaluation waste.
  - Benchmarked against state-of-the-art double-array indexed peer `rsigma-eval` v0.27.0 across 1,110 common rules and 2,427 Windows rules: 1.04× to 2.01× faster on single-core process/attack telemetry, 5.15× faster on linear payload scans (255.60 µs vs 1,317.20 µs at 64 KiB), and 626× faster on bypassed telemetry (1.02 µs vs 640.24 µs via $O(1)$ fast prune).
  - SMP concurrency scaling reached **138,665 EPS** on 8 SMT threads (4.88× speedup).
  - All 308 tests across 9 workspace targets pass with zero failures and zero warnings under `#![forbid(unsafe_code)]`.
- **v0.2.0 Engineering Roadmap (Active Frontiers):**
  - **Category Witness-Key Early Pruning:** Check partition's 64-bit `present_fields_mask` against required rule field bits *before* invoking the Bloom hasher to exit non-matching events in $<50$ nanoseconds (closing the sub-microsecond margin in Windows Network & DNS).
  - **SIMD-Accelerated Bitset Operations:** Vectorized `RuleBitSet` operations for multi-pattern candidate generation.

**Explicitly parked until after publish:**

- **D** — Python bindings / Sigma v2 correlation: too early before install
- **A1** — dedicated-metal supersession of §11.12: paper/v1 polish, not code path

Harness `null_sigma_run` remains the Tier B **count-only** bench runner.

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
- SigmaHQ / vendored rule corpora are dev-only inputs — gitignored, never
  committed, never a runtime dependency. Small synthetic fixtures under
  `tests/fixtures/` (robustness JSONL, minimal rules) are committed CI inputs
  only — not corpus vendoring.
