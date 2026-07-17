# null-sigma head-to-head benchmark harness

Roadmap item 3. Compares **null-sigma**, **tau-engine** (Chainsaw's matching
core), and **sigma-rust** on the same SigmaHQ rules and seeded event stream.
Also measures CLI end-to-end wall-clock vs Hayabusa and Chainsaw.

The harness is a standalone crate — it does not modify the core library except
to consume it. For the installable product CLI (alerts on stdout), see
[`cli/`](../cli/) (`null-sigma-cli`); `null_sigma_run` here is the Tier B
count-only bench / trust runner.

## Prerequisites

```bash
# SigmaHQ corpus (dev-only, gitignored)
git clone --depth 1 https://github.com/SigmaHQ/sigma.git corpus/sigmahq

# Tier B only
brew install hyperfine
```

## Measurement tiers

| Tier | What | Command | Comparable? |
|---|---|---|---|
| **0** | Synthetic micro-rules (prefilter scaling) | `cargo bench --bench sigma_bench` (root crate) | Internal only |
| **A** | Matcher-level, real rules, library APIs | `cargo bench --bench head_to_head` | null-sigma vs tau vs sigma-rust |
| **B** | Full CLI wall-clock (count-only harness) | `./scripts/run_cli_bench.sh` | Includes parse/enrich/output |
| **B-product** | Product CLI alerts vs Hayabusa | `./scripts/run_product_cli_bench.sh` | §11.12 — quiet corpus |
| **A4** | Controlled hit-rate tax / Falcon slope | `./scripts/run_a4_firehose_sweep.sh` | §11.13 — sibling to B-product |

**Never conflate meters.** Tier A times only the matching call with pre-built
native event representations. Tier B / B-product / A4 include pipeline costs;
A4 must not overwrite §11.12 numbers.

## Correctness gate (run first)

```bash
cd harness
cargo run --release --bin cross_check
```

Loads SigmaHQ `rules/windows/process_creation` (1 182 files) into all three
engines, evaluates every common rule against 2 000 seeded events, and reports
pairwise disagreements.

Latest result (2026-07-07):

| Pair | Disagreements | Rate |
|---|---|---|
| null-sigma vs sigma-rust | **0** | 0.0000% |
| null-sigma vs tau-engine | 13 | 0.0006% |
| tau-engine vs sigma-rust | 13 | 0.0006% |

The 13 cells are all on `Suspicious SYSTEM User Process Creation` — attributable
to Chainsaw converter semantics, not an engine bug in null-sigma.

Load compatibility:

| Engine | Loaded | Rate |
|---|---|---|
| null-sigma | 1 182 | 100.0% |
| tau-engine (Chainsaw converter) | 1 102 | 93.2% |
| sigma-rust | 1 181 | 99.9% |

## Tier A — Criterion (matcher-level)

```bash
cd harness
cargo bench --bench head_to_head
```

Benchmarks (1 102 common rules, seed-42 events, Apple M4, release, 2026-07-08):

| Benchmark | null-sigma | tau-engine | sigma-rust |
|---|---|---|---|
| `single_benign_event` | **309 µs** | **136 µs** | 4.61 ms |
| `batch_1000_events` | 373 ms | 142 ms | 3.94 s |
| `rule_load` | 71 ms | 200 ms | 43 ms |

null-sigma also benchmarks `null_sigma_full` with all 1 182 rules it loads
(`single_benign_event/null_sigma_full`: ~369 µs).

Interactive HTML: `harness/target/criterion/report/index.html`

## Profiling gate (local only)

Tier A `prof_benign` — same workload as `single_benign_event`. Run before and
after matcher changes to validate hotspot shifts. Output under `harness/prof/`
(gitignored).

```bash
cargo install samply   # once
cd harness && ./scripts/prof_benign.sh
```

Produces:
- `prof/samply_*.json.gz` — open with `samply load …` (Firefox Profiler)
- `prof/sample_*.txt` — run `sample $BPID` during the 100k loop for symbolicated stacks (see script output)
- `prof/summary_*.txt` — fill after review (template: `scripts/prof_NOTES.template.md`)

Do not commit `harness/prof/` artifacts.

## Tier B — CLI end-to-end (hyperfine)

```bash
cd harness
./scripts/run_cli_bench.sh          # default: 100k events, seed 42
EVENTS=10000 ./scripts/run_cli_bench.sh   # smaller smoke run

# Trust-policy smoke (mixed good/bad JSONL)
./scripts/smoke_error_policy.sh

# Day 2 robustness corpus (depth/field guards, line limit)
./scripts/smoke_robustness.sh

# Day 3 determinism gate (identical ingest accounting across two runs)
./scripts/smoke_determinism.sh

# Day 4 hermetic trust umbrella (committed rules + robustness fixtures)
./scripts/smoke_trust.sh
```

**CI:** every push/PR to `main` runs the `Harness trust smoke` job
(`.github/workflows/ci.yml`): `cargo test` in `harness/` plus
`./scripts/smoke_trust.sh`. Hermetic — committed fixtures only; no SigmaHQ
clone. Local `./scripts/smoke_trust.sh` is the same gate developers run.

Downloads pinned binaries to `harness/bin/` (gitignored):

- Hayabusa **3.9.0** (native aarch64)
- Chainsaw **2.13.1** (x86_64 under Rosetta 2 on Apple Silicon — noted in report)

Dataset: deterministic flat JSONL (`gen_dataset` binary, seed 42).

Latest hyperfine (100k events, **2026-07-13**, Rayon; warmup 1 + 5 runs).
Prior published baseline (2026-07-08): default-threads 15.2 s / ~1.57× vs Hayabusa.

| Command | Mean | Events/sec |
|---|---|---|
| `null-sigma-runner-default-threads` | **7.257 s ± 0.044** | **13 780** |
| `null-sigma-runner-4-thread` | 11.502 s ± 0.475 | 8 690 |
| `hayabusa-default-threads` | 15.534 s ± 0.239 | 6 440 |
| `chainsaw-hunt` | 28.370 s ± 0.719 | 3 530 |
| `null-sigma-runner` | **36.616 s ± 0.158** | **2 730** |
| `hayabusa-1-thread` | 54.403 s ± 1.457 | 1 840 |

**Single-thread win:** null-sigma ~1.49× faster than Hayabusa `--threads 1`.
**Multi-thread win:** null-sigma `--threads 0` ~2.14× faster than Hayabusa default.
Parity gate: `./scripts/smoke_parallel.sh` (10k events, threads 1/2/4/8/0).
Tax split: **eval 99%** — see `PERFORMANCE.md` §11.5a.

Written to `harness/data/tier_b_results.md` (gitignored).

### Tier B-product — `null-sigma-cli` (≠ harness Tier B)

Measures the **installable product** path: lean NDJSON alerts → `/dev/null`,
same SigmaHQ `process_creation` + seed-42 JSONL, vs pinned Hayabusa 3.9.0.
Includes a count-only `null_sigma_run` row so the **emit / pipeline tax** is
visible. **Do not** paste results into the harness Tier B table above.

```bash
cd harness
EVENTS=100000 ./scripts/run_product_cli_bench.sh   # candidate (prefer Linux)
EVENTS=5000 ./scripts/run_product_cli_bench.sh     # local pilot / smoke
```

Artifacts (gitignored): `data/tier_b_product_meta.txt`,
`data/tier_b_product_results.md` (science header + hyperfine markdown).

**CI:** Actions → **Product CLI bench** (`workflow_dispatch` only; not on
push/PR). Download the artifact and compare to `PERFORMANCE.md` §11.12.
Label GHA numbers as shared-metal noise.

**Inked (2026-07-14 GHA):** see `PERFORMANCE.md` §11.12 — count-only ceiling
**27.97 s**, CLI default **28.84 s** (~1.03× tax), Hayabusa default **51.69 s**.
Protocol, pilot disposition, and regression markers live in that section.

### A4 Alert-Firehose Sweep (§11.13 — sibling to B-product)

Controlled event-hit rate \(p \in \{1\%,10\%,50\%\}\) with multiplicity
\(m \approx 1\) (one rule: `tests/fixtures/rules/a4_hit/`). Measures **H1 tax**
and **H2 Falcon** independently. Does **not** replace §11.12.

```bash
cd harness
EVENTS=5000 ./scripts/run_a4_firehose_sweep.sh      # pilot / script smoke
EVENTS=100000 ./scripts/run_a4_firehose_sweep.sh    # candidate (prefer Linux)
```

Artifacts: `data/a4_meta.txt`, `data/a4_slope.csv`, `data/a4_results.md`.
Generator: `gen_dataset … --a4-hit-bpm N`. CI: Actions → **A4 firehose sweep**
(`workflow_dispatch`). Full protocol + gates: `PERFORMANCE.md` §11.13.

### Chainsaw JSON mapping

Chainsaw's bundled EVTX mapping expects nested `Event.System.*` documents.
For JSONL input we ship `config/chainsaw-json-mapping.yml` (`kind: json`) so
flat nxlog-style records produce non-zero detections. Without it, Chainsaw
silently matches nothing on JSONL and looks artificially fast.

## Binaries

| Binary | Purpose |
|---|---|
| `cross_check` | Correctness gate — run before publishing numbers |
| `null_sigma_run` | Tier B reference CLI (`[--threads N] [--on-error continue\|fail-fast] [--max-line-bytes N] [--max-error-samples N] rule_dir events.jsonl`); prints `tier_b_tax` + honest ingest error accounting |
| `gen_dataset` | Deterministic JSONL event generator |
| `prof_benign` | Tier A profiling target (`--profile prof`) |

Scripts: `scripts/smoke_parallel.sh` (thread-count parity on 10k events;
requires SigmaHQ + generated dataset — not in CI),
`scripts/smoke_trust.sh` (hermetic trust umbrella; CI-enforced),
`scripts/smoke_error_policy.sh` (continue/fail-fast trust checks),
`scripts/smoke_robustness.sh` (malformed corpus + guard checks; asserts
`ingest_errors` line parity across `--threads 1` and `--threads 0`),
`scripts/smoke_determinism.sh` (identical `ingest_errors` / `ingest_accounting`
across two runs on the mixed fixture).

### Trust-first ingestion policy

- Default mode is `--on-error continue`: event-level parse/flatten/read errors
  are counted and reported, and the run completes.
- `--on-error fail-fast` exits non-zero on the first event-level error.
- Startup/config errors (cannot read rules/events file) always exit non-zero.
- Summary accounting invariant (`events_total = events_ok + events_failed`) is
  reported on stderr and **enforced**: violation prints `FATAL:` and exits 1
  before match output.
- Flatten failures are split honestly:
  `flatten_not_object`, `flatten_depth`, `flatten_fields`.
- `--max-line-bytes` (default 8 MiB) rejects oversize JSONL lines before parse.
  Enforced after `read_line`, so it blocks JSON parse/flatten heap growth but not
  line-buffer allocation on pathological unterminated lines; bounded byte-loop
  ingest is deferred to Phase 3 streaming rewrite.
- Ingest error counters are single-threaded (no atomics); Rayon parallelizes eval only.
- `--max-error-samples N` (default 0) emits up to N `ingest_error_sample:` lines
  during ingest for debugging (`line`, `kind`, `msg`); does not affect counters
  or exit codes. Samples are deterministic for a given input file.
- Malformed corpus fixtures live in `tests/fixtures/robustness/` (see README there).
- Trust smokes default to committed synthetic rules in
  `tests/fixtures/rules/minimal/` (hermetic CI). Override with
  `RULE_DIR=corpus/sigmahq/rules/windows/process_creation` for local Tier B runs.
- Rust integration tests: from `harness/`, run `cargo test` (`tests/runner_trust.rs`).
  (Harness is its own Cargo workspace — not `-p` from the repo root.)
- CI enforces trust via the `trust-smoke` job (Days 1–5 Week 1 closeout).

### Stderr contract (`null_sigma_run`)

Stable stderr layout (stdout is match count only):

**During ingest** (when `--max-error-samples N > 0`):

- `ingest_error_sample:` — up to N lines as failures occur (`line`, `kind`, `msg`)

**End of run** (always, in order):

1. `rules:` — load summary, thread/error policy, scan timing
2. `tier_b_tax:` — read / parse / flat / eval / other timing split
3. `ingest_errors:` — `io_read`, `line_too_large`, `json_parse`,
   `flatten_not_object`, `flatten_depth`, `flatten_fields`, `flatten_total`, `total`
4. `ingest_accounting:` — `events_total`, `events_ok`, `events_failed`, `invariant_ok`

Exit codes:

| Condition | Code |
|---|---|
| Bad CLI arguments | 2 |
| Startup/config failure (rules, events file, Rayon pool) | 1 |
| `--on-error fail-fast` on first event error | 1 |
| Accounting invariant violation | 1 |
| `--on-error continue` with event errors, scan completes | 0 |

Determinism gate: `smoke_determinism.sh` asserts `ingest_errors` and
`ingest_accounting` lines are identical across two consecutive runs.

## Layout

```
harness/
├── benches/head_to_head.rs    # Tier A
├── src/
│   ├── lib.rs                 # Engine wrappers, rule compatibility
│   ├── convert.rs             # Sigma → tau (Chainsaw path)
│   └── gen.rs                 # Event generator
├── src/bin/
│   ├── cross_check.rs
│   ├── null_sigma_run.rs
│   ├── gen_dataset.rs
│   └── prof_benign.rs         # Profiling gate (local)
├── scripts/
│   ├── run_cli_bench.sh       # Tier B harness (count-only)
│   ├── run_product_cli_bench.sh  # Tier B-product (null-sigma-cli alerts)
│   ├── run_a4_firehose_sweep.sh  # A4 tax/Falcon slope (§11.13)
│   ├── smoke_parallel.sh      # Thread-count parity (10k)
│   ├── smoke_error_policy.sh  # continue/fail-fast policy
│   ├── smoke_robustness.sh    # malformed corpus + guards
│   ├── smoke_determinism.sh   # ingest accounting determinism
│   ├── smoke_trust.sh         # hermetic trust umbrella (Day 4)
│   ├── lib/rule_dir.sh        # RULE_DIR resolver (default minimal rules)
│   └── prof_benign.sh         # samply profiling (local output → prof/)
├── prof/                      # gitignored — profiles + summary notes
├── config/chainsaw-json-mapping.yml
└── data/                      # gitignored — tier_b_*.md / product_* / datasets
```

Full performance analysis: `../PERFORMANCE.md` §11 (§11.12 = Tier B-product;
§11.13 = A4 firehose sweep).
